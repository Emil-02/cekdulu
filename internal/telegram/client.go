// Package telegram is a CekDulu bot for Telegram: users forward suspicious
// messages, links, phone numbers or APK files and get an explainable risk
// verdict back, and can file community reports through a short conversation.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultAPIBase is the public Bot API endpoint.
const DefaultAPIBase = "https://api.telegram.org"

// MaxDownloadSize is the Bot API limit for getFile downloads.
const MaxDownloadSize = 20 << 20

// Client calls the Telegram Bot API. Errors never contain the bot token.
type Client struct {
	token string
	base  string
	http  *http.Client
}

// NewClient returns a client. base defaults to DefaultAPIBase.
func NewClient(token, base string, hc *http.Client) *Client {
	if base == "" {
		base = DefaultAPIBase
	}
	if hc == nil {
		hc = &http.Client{Timeout: 90 * time.Second}
	}
	return &Client{token: token, base: strings.TrimRight(base, "/"), http: hc}
}

// APIError is an error response from Telegram.
type APIError struct {
	Method      string
	Code        int
	Description string
	RetryAfter  int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("telegram %s: %d %s", e.Method, e.Code, e.Description)
}

// scrub removes the token from transport errors (url.Error embeds the URL).
func (c *Client) scrub(method string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := strings.ReplaceAll(err.Error(), c.token, "<token>")
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("telegram %s: %w", method, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("telegram %s: %w", method, context.DeadlineExceeded)
	}
	return fmt.Errorf("telegram %s: %s", method, msg)
}

// Call invokes method with params (JSON) and decodes the result into out.
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+c.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return c.scrub(method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return c.scrub(method, err)
	}
	defer resp.Body.Close()
	var env struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&env); err != nil {
		return fmt.Errorf("telegram %s: respons tidak valid (HTTP %d)", method, resp.StatusCode)
	}
	if !env.OK {
		code := env.ErrorCode
		if code == 0 {
			code = resp.StatusCode
		}
		return &APIError{Method: method, Code: code, Description: env.Description, RetryAfter: env.Parameters.RetryAfter}
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("telegram %s: hasil tidak valid: %v", method, err)
		}
	}
	return nil
}

// Types below cover only the fields the bot uses.

type User struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username,omitempty"`
}

type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// Private reports whether the chat is a one-to-one chat with the bot.
func (c Chat) Private() bool { return c.Type == "private" }

type Entity struct {
	Type   string `json:"type"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	URL    string `json:"url,omitempty"`
}

type Document struct {
	FileID   string `json:"file_id"`
	FileName string `json:"file_name,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
	FileSize int64  `json:"file_size,omitempty"`
}

type Message struct {
	MessageID       int64     `json:"message_id"`
	From            *User     `json:"from,omitempty"`
	Chat            Chat      `json:"chat"`
	Text            string    `json:"text,omitempty"`
	Entities        []Entity  `json:"entities,omitempty"`
	Caption         string    `json:"caption,omitempty"`
	CaptionEntities []Entity  `json:"caption_entities,omitempty"`
	Document        *Document `json:"document,omitempty"`
	ReplyToMessage  *Message  `json:"reply_to_message,omitempty"`
}

// Content returns the text or caption with its entities.
func (m *Message) Content() (string, []Entity) {
	if m.Text != "" {
		return m.Text, m.Entities
	}
	return m.Caption, m.CaptionEntities
}

type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message,omitempty"`
	Data    string   `json:"data,omitempty"`
}

type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message,omitempty"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

type InlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type InlineKeyboard struct {
	Rows [][]InlineButton `json:"inline_keyboard"`
}

// Outgoing is a sendMessage request.
type Outgoing struct {
	ChatID      int64           `json:"chat_id"`
	Text        string          `json:"text"`
	ParseMode   string          `json:"parse_mode,omitempty"`
	ReplyMarkup *InlineKeyboard `json:"reply_markup,omitempty"`
	ReplyTo     *struct {
		MessageID                int64 `json:"message_id"`
		AllowSendingWithoutReply bool  `json:"allow_sending_without_reply"`
	} `json:"reply_parameters,omitempty"`
	LinkPreview struct {
		Disabled bool `json:"is_disabled"`
	} `json:"link_preview_options"`
}

// GetUpdates long-polls for updates after offset.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout int) ([]Update, error) {
	var out []Update
	err := c.Call(ctx, "getUpdates", map[string]any{
		"offset":          offset,
		"timeout":         timeout,
		"allowed_updates": []string{"message", "callback_query"},
	}, &out)
	return out, err
}

// Send posts a message as HTML with link previews disabled.
func (c *Client) Send(ctx context.Context, m Outgoing) error {
	m.ParseMode = "HTML"
	m.LinkPreview.Disabled = true
	return c.Call(ctx, "sendMessage", m, nil)
}

// AnswerCallback acknowledges a button press.
func (c *Client) AnswerCallback(ctx context.Context, id, text string) error {
	return c.Call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

// Download fetches a file by file_id, up to MaxDownloadSize bytes.
func (c *Client) Download(ctx context.Context, fileID string) ([]byte, error) {
	var f struct {
		FilePath string `json:"file_path"`
		FileSize int64  `json:"file_size"`
	}
	if err := c.Call(ctx, "getFile", map[string]string{"file_id": fileID}, &f); err != nil {
		return nil, err
	}
	if f.FilePath == "" {
		return nil, fmt.Errorf("telegram getFile: file tidak tersedia")
	}
	if f.FileSize > MaxDownloadSize {
		return nil, fmt.Errorf("file lebih dari %d MB", MaxDownloadSize>>20)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/file/bot"+c.token+"/"+f.FilePath, nil)
	if err != nil {
		return nil, c.scrub("download", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.scrub("download", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram download: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownloadSize+1))
	if err != nil {
		return nil, c.scrub("download", err)
	}
	if len(data) > MaxDownloadSize {
		return nil, fmt.Errorf("file lebih dari %d MB", MaxDownloadSize>>20)
	}
	return data, nil
}

// Typing shows the "typing..." indicator in a chat.
func (c *Client) Typing(ctx context.Context, chatID int64) error {
	return c.Call(ctx, "sendChatAction", map[string]any{"chat_id": chatID, "action": "typing"}, nil)
}
