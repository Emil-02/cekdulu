package report

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/Emil-02/cekdulu/supabase"
)

func TestMemoryStore(t *testing.T) {
	testStore(t, NewMemory())
}

// TestPostgresStore runs against a real database when
// CEKDULU_TEST_DATABASE_URL is set. The database is wiped first.
func TestPostgresStore(t *testing.T) {
	dsn := os.Getenv("CEKDULU_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CEKDULU_TEST_DATABASE_URL belum diatur")
	}
	ctx := context.Background()
	p, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Migrate(ctx, supabase.Migrations); err != nil {
		t.Fatal(err)
	}
	// A second run must be a no-op.
	if err := p.Migrate(ctx, supabase.Migrations); err != nil {
		t.Fatalf("migrasi ulang: %v", err)
	}
	if _, err := p.pool.Exec(ctx, `truncate indicators, reports, evidence, appeals, moderation_log`); err != nil {
		t.Fatal(err)
	}
	testStore(t, p)

	var logged int
	if err := p.pool.QueryRow(ctx, `select count(*) from moderation_log`).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if logged == 0 {
		t.Error("keputusan moderator tidak tercatat di moderation_log")
	}
}

func testStore(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	phone := Indicator{Kind: KindPhone, Hash: "hash-phone-1", Display: "0812****7890"}
	desc := "Mengaku kurir dan meminta saya membuka APK undangan."
	loss := int64(150000)

	if _, err := s.Lookup(ctx, KindPhone, phone.Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup awal: %v", err)
	}

	r1, err := s.CreateReport(ctx, NewReport{
		Indicator: phone, Category: "impersonation", Description: desc, LossAmount: &loss,
		ContactHash: "c1", IPHash: "ip1",
		Evidence: []Evidence{{StorageKey: "evidence/a.png", SHA256: "abc", MIME: "image/png", Size: 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Status != StatusPending || r1.Display != phone.Display || r1.Kind != KindPhone {
		t.Fatalf("laporan baru: %+v", r1)
	}
	if len(r1.Evidence) != 1 || r1.Evidence[0].ID == "" || r1.Evidence[0].StorageKey != "evidence/a.png" {
		t.Fatalf("bukti: %+v", r1.Evidence)
	}
	if r1.SameReporterCount < 1 {
		t.Errorf("SameReporterCount = %d", r1.SameReporterCount)
	}
	if _, err := s.Lookup(ctx, KindPhone, phone.Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("laporan pending tidak boleh tampil: %v", err)
	}

	pending, err := s.ListReports(ctx, StatusPending, 10, 0)
	if err != nil || len(pending) != 1 || pending[0].ID != r1.ID {
		t.Fatalf("ListReports pending = %+v, %v", pending, err)
	}

	got, err := s.Decide(ctx, r1.ID, true, "emil", "bukti cukup")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.ReviewedBy != "emil" || got.ReviewNote != "bukti cukup" || got.ReviewedAt == nil {
		t.Fatalf("keputusan: %+v", got)
	}
	if _, err := s.Decide(ctx, r1.ID, false, "emil", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("keputusan ganda: %v", err)
	}
	if _, err := s.Decide(ctx, "00000000-0000-4000-8000-000000000000", true, "emil", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("id tidak ada: %v", err)
	}
	if _, err := s.Decide(ctx, "bukan-uuid", true, "emil", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("id tidak valid: %v", err)
	}

	st, err := s.Lookup(ctx, KindPhone, phone.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if st.ApprovedCount != 1 || st.Status != IndicatorActive || !slices.Equal(st.Categories, []string{"impersonation"}) {
		t.Fatalf("lookup: %+v", st)
	}

	// Domains: a rejected report must not reach the blocklist.
	bad := Indicator{Kind: KindDomain, Hash: "bca-hadiah.xyz", Display: "bca-hadiah.xyz"}
	spam := Indicator{Kind: KindDomain, Hash: "toko-aman.com", Display: "toko-aman.com"}
	rb, err := s.CreateReport(ctx, NewReport{Indicator: bad, Category: "phishing", Description: desc})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := s.CreateReport(ctx, NewReport{Indicator: spam, Category: "online_shop", Description: desc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, rb.ID, true, "emil", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, rs.ID, false, "emil", "tidak ada bukti"); err != nil {
		t.Fatal(err)
	}
	bl, err := s.Blocklist(ctx, KindDomain)
	if err != nil || !slices.Equal(bl, []string{"bca-hadiah.xyz"}) {
		t.Fatalf("blocklist = %v, %v", bl, err)
	}
	if _, err := s.Blocklist(ctx, KindPhone); err == nil {
		t.Fatal("blocklist nomor HP tidak boleh tersedia")
	}

	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.ApprovedReports != 2 || stats.PendingReports != 0 || stats.TotalLoss != loss ||
		stats.Indicators[KindPhone] != 1 || stats.Indicators[KindDomain] != 1 || stats.Categories["phishing"] != 1 {
		t.Fatalf("stats: %+v", stats)
	}

	// Appeals: rejected keeps the indicator, accepted removes it.
	if _, err := s.CreateAppeal(ctx, NewAppeal{Indicator: spam, Contact: "x@y.id", Reason: desc}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sanggahan untuk indikator tanpa laporan disetujui: %v", err)
	}
	a1, err := s.CreateAppeal(ctx, NewAppeal{Indicator: phone, Contact: "pemilik@contoh.id", Reason: desc})
	if err != nil {
		t.Fatal(err)
	}
	if a1.Status != AppealPending || a1.Display != phone.Display {
		t.Fatalf("sanggahan: %+v", a1)
	}
	if st, _ := s.Lookup(ctx, KindPhone, phone.Hash); st.Status != IndicatorDisputed {
		t.Fatalf("status setelah sanggahan = %q", st.Status)
	}
	list, err := s.ListAppeals(ctx, AppealPending, 0, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAppeals = %+v, %v", list, err)
	}
	if _, err := s.ResolveAppeal(ctx, a1.ID, false, "emil", ""); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Lookup(ctx, KindPhone, phone.Hash); st.Status != IndicatorActive {
		t.Fatalf("status setelah sanggahan ditolak = %q", st.Status)
	}
	a2, err := s.CreateAppeal(ctx, NewAppeal{Indicator: phone, Contact: "pemilik@contoh.id", Reason: desc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAppeal(ctx, a2.ID, true, "emil", "nomor sudah berganti pemilik"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAppeal(ctx, a2.ID, true, "emil", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("sanggahan ganda: %v", err)
	}
	if _, err := s.Lookup(ctx, KindPhone, phone.Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("indikator yang dihapus masih tampil: %v", err)
	}
}
