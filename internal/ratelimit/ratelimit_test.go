package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := New(Rate{N: 2, Per: time.Minute}, func() time.Time { return now })
	if !l.Allow("a") || !l.Allow("a") || l.Allow("a") {
		t.Fatal("budget 2 per menit tidak ditegakkan")
	}
	if !l.Allow("b") {
		t.Fatal("kunci lain harus punya budget sendiri")
	}
	now = now.Add(time.Minute)
	if !l.Allow("a") {
		t.Fatal("budget harus pulih setelah jendela berakhir")
	}
	var nilLimiter *Limiter
	if !nilLimiter.Allow("x") || !New(Rate{}, nil).Allow("x") {
		t.Fatal("limiter nil/tanpa batas harus mengizinkan")
	}
}
