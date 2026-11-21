package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Emil-02/cekdulu/internal/blob"
	"github.com/Emil-02/cekdulu/internal/report"
)

func listParams(r *http.Request, statuses ...string) (status string, limit, offset int, err error) {
	q := r.URL.Query()
	status = q.Get("status")
	switch status {
	case "":
		status = statuses[0]
	case "all":
		status = ""
	default:
		valid := false
		for _, s := range statuses {
			valid = valid || s == status
		}
		if !valid {
			return "", 0, 0, badRequest("status %q tidak dikenal", status)
		}
	}
	if v := q.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 {
			return "", 0, 0, badRequest("limit harus angka positif")
		}
	}
	if v := q.Get("offset"); v != "" {
		if offset, err = strconv.Atoi(v); err != nil || offset < 0 {
			return "", 0, 0, badRequest("offset harus angka >= 0")
		}
	}
	return status, limit, offset, nil
}

func decision(r *http.Request, yes, no string) (bool, error) {
	switch r.PathValue("action") {
	case yes:
		return true, nil
	case no:
		return false, nil
	}
	return false, notFound(fmt.Sprintf("aksi harus %s atau %s", yes, no))
}

func readNote(w http.ResponseWriter, r *http.Request) (string, error) {
	var body struct {
		Note string `json:"note"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		return "", err
	}
	if len([]rune(body.Note)) > MaxNoteLen {
		return "", badRequest("note maksimal %d karakter", MaxNoteLen)
	}
	return body.Note, nil
}

func (s *Server) handleAdminListReports(w http.ResponseWriter, r *http.Request, _ string) error {
	status, limit, offset, err := listParams(r, report.StatusPending, report.StatusApproved, report.StatusRejected)
	if err != nil {
		return err
	}
	reports, err := s.opt.Store.ListReports(r.Context(), status, limit, offset)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
	return nil
}

func (s *Server) handleAdminGetReport(w http.ResponseWriter, r *http.Request, _ string) error {
	rep, err := s.opt.Store.GetReport(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, rep)
	return nil
}

func (s *Server) handleAdminDecide(w http.ResponseWriter, r *http.Request, actor string) error {
	approve, err := decision(r, "approve", "reject")
	if err != nil {
		return err
	}
	note, err := readNote(w, r)
	if err != nil {
		return err
	}
	rep, err := s.opt.Store.Decide(r.Context(), r.PathValue("id"), approve, actor, note)
	if err != nil {
		return err
	}
	s.log.Info("laporan diputuskan", "report", rep.ID, "status", rep.Status, "moderator", actor)
	writeJSON(w, http.StatusOK, rep)
	return nil
}

func (s *Server) handleAdminEvidence(w http.ResponseWriter, r *http.Request, _ string) error {
	if s.opt.Blobs == nil {
		return notFound("penyimpanan bukti belum diaktifkan")
	}
	rep, err := s.opt.Store.GetReport(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	for _, e := range rep.Evidence {
		if e.ID != r.PathValue("evidence") {
			continue
		}
		data, err := s.opt.Blobs.Get(r.Context(), e.StorageKey)
		if errors.Is(err, blob.ErrNotFound) {
			return notFound("file bukti tidak ditemukan di penyimpanan")
		}
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", e.MIME)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="bukti-%s%s"`, e.ID, evidenceTypes[e.MIME]))
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
		_, _ = w.Write(data)
		return nil
	}
	return notFound("bukti tidak ditemukan pada laporan ini")
}

func (s *Server) handleAdminListAppeals(w http.ResponseWriter, r *http.Request, _ string) error {
	status, limit, offset, err := listParams(r, report.AppealPending, report.AppealAccepted, report.AppealRejected)
	if err != nil {
		return err
	}
	appeals, err := s.opt.Store.ListAppeals(r.Context(), status, limit, offset)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"appeals": appeals})
	return nil
}

func (s *Server) handleAdminResolveAppeal(w http.ResponseWriter, r *http.Request, actor string) error {
	accept, err := decision(r, "accept", "reject")
	if err != nil {
		return err
	}
	note, err := readNote(w, r)
	if err != nil {
		return err
	}
	a, err := s.opt.Store.ResolveAppeal(r.Context(), r.PathValue("id"), accept, actor, note)
	if err != nil {
		return err
	}
	s.log.Info("sanggahan diputuskan", "appeal", a.ID, "status", a.Status, "moderator", actor)
	writeJSON(w, http.StatusOK, a)
	return nil
}
