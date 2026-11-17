package report

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is a Store backed by PostgreSQL (e.g. Supabase).
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects to dsn.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_URL tidak valid: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

// Migrate applies *.sql files from fsys (root directory "migrations") that
// were not applied yet, each in its own transaction.
func (p *Postgres) Migrate(ctx context.Context, fsys fs.FS) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `select pg_advisory_lock(727274)`); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), `select pg_advisory_unlock(727274)`) }()

	if _, err := conn.Exec(ctx, `create table if not exists cekdulu_migrations (
		version text primary key, applied_at timestamptz not null default now())`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var exists bool
		if err := conn.QueryRow(ctx, `select exists(select 1 from cekdulu_migrations where version=$1)`, name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, err := fs.ReadFile(fsys, "migrations/"+name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrasi %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `insert into cekdulu_migrations(version) values ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) Close() error {
	p.pool.Close()
	return nil
}

func (p *Postgres) Lookup(ctx context.Context, kind, hash string) (IndicatorStat, error) {
	var s IndicatorStat
	err := p.pool.QueryRow(ctx, `
		select i.kind::text, i.display, i.approved_count, i.status::text, i.first_seen, i.last_seen,
		       coalesce(array(select distinct r.category from reports r
		                      where r.indicator_id = i.id and r.status = 'approved' order by 1), '{}')
		from indicators i
		where i.kind = $1 and i.value_hash = $2 and i.approved_count > 0 and i.status <> 'removed'`,
		kind, hash).Scan(&s.Kind, &s.Display, &s.ApprovedCount, &s.Status, &s.FirstSeen, &s.LastSeen, &s.Categories)
	if errors.Is(err, pgx.ErrNoRows) {
		return IndicatorStat{}, ErrNotFound
	}
	return s, err
}

func (p *Postgres) CreateReport(ctx context.Context, nr NewReport) (Report, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var indID string
	err = tx.QueryRow(ctx, `
		insert into indicators (kind, value_hash, display) values ($1, $2, $3)
		on conflict (kind, value_hash) do update set display = indicators.display
		returning id`, nr.Indicator.Kind, nr.Indicator.Hash, nr.Indicator.Display).Scan(&indID)
	if err != nil {
		return Report{}, err
	}
	var id string
	err = tx.QueryRow(ctx, `
		insert into reports (indicator_id, category, description, loss_amount, contact_hash, ip_hash)
		values ($1, $2, $3, $4, nullif($5, ''), nullif($6, '')) returning id`,
		indID, nr.Category, nr.Description, nr.LossAmount, nr.ContactHash, nr.IPHash).Scan(&id)
	if err != nil {
		return Report{}, err
	}
	for _, e := range nr.Evidence {
		if _, err := tx.Exec(ctx, `insert into evidence (report_id, storage_key, sha256, mime, size) values ($1,$2,$3,$4,$5)`,
			id, e.StorageKey, e.SHA256, e.MIME, e.Size); err != nil {
			return Report{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Report{}, err
	}
	return p.GetReport(ctx, id)
}

const reportCols = `
	r.id::text, i.kind::text, i.display, r.category, r.description, r.loss_amount, r.status::text,
	r.created_at, r.reviewed_at, coalesce(r.reviewed_by, ''), coalesce(r.review_note, ''),
	(select count(*) from reports o where o.created_at > now() - interval '24 hours'
	   and ((r.contact_hash is not null and o.contact_hash = r.contact_hash)
	     or (r.ip_hash is not null and o.ip_hash = r.ip_hash)))`

func scanReport(row pgx.Row) (Report, error) {
	var r Report
	err := row.Scan(&r.ID, &r.Kind, &r.Display, &r.Category, &r.Description, &r.LossAmount, &r.Status,
		&r.CreatedAt, &r.ReviewedAt, &r.ReviewedBy, &r.ReviewNote, &r.SameReporterCount)
	return r, err
}

func (p *Postgres) evidence(ctx context.Context, reportID string) ([]Evidence, error) {
	rows, err := p.pool.Query(ctx, `select id::text, storage_key, sha256, mime, size, created_at
		from evidence where report_id = $1 order by created_at, id`, reportID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Evidence, error) {
		var e Evidence
		err := row.Scan(&e.ID, &e.StorageKey, &e.SHA256, &e.MIME, &e.Size, &e.CreatedAt)
		return e, err
	})
}

func (p *Postgres) GetReport(ctx context.Context, id string) (Report, error) {
	if !isUUID(id) {
		return Report{}, ErrNotFound
	}
	r, err := scanReport(p.pool.QueryRow(ctx, `select `+reportCols+`
		from reports r join indicators i on i.id = r.indicator_id where r.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, err
	}
	if r.Evidence, err = p.evidence(ctx, r.ID); err != nil {
		return Report{}, err
	}
	return r, nil
}

func (p *Postgres) ListReports(ctx context.Context, status string, limit, offset int) ([]Report, error) {
	rows, err := p.pool.Query(ctx, `select `+reportCols+`
		from reports r join indicators i on i.id = r.indicator_id
		where ($1 = '' or r.status::text = $1)
		order by r.created_at, r.id limit $2 offset $3`, status, clampLimit(limit), max(offset, 0))
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Report, error) { return scanReport(row) })
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Evidence, err = p.evidence(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []Report{}
	}
	return out, nil
}

func (p *Postgres) Decide(ctx context.Context, id string, approve bool, actor, note string) (Report, error) {
	if !isUUID(id) {
		return Report{}, ErrNotFound
	}
	status, action := StatusRejected, "reject"
	if approve {
		status, action = StatusApproved, "approve"
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var indID string
	err = tx.QueryRow(ctx, `
		update reports set status = $2::report_status, reviewed_at = now(), reviewed_by = $3, review_note = nullif($4, '')
		where id = $1 and status = 'pending' returning indicator_id::text`, id, status, actor, note).Scan(&indID)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := tx.QueryRow(ctx, `select exists(select 1 from reports where id = $1)`, id).Scan(&exists); err != nil {
			return Report{}, err
		}
		if !exists {
			return Report{}, ErrNotFound
		}
		return Report{}, ErrConflict
	}
	if err != nil {
		return Report{}, err
	}
	if approve {
		if _, err := tx.Exec(ctx, `update indicators set approved_count = approved_count + 1, last_seen = now(),
			status = 'active' where id = $1`, indID); err != nil {
			return Report{}, err
		}
	}
	if err := logAction(ctx, tx, "report", id, action, actor, note); err != nil {
		return Report{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Report{}, err
	}
	return p.GetReport(ctx, id)
}

func logAction(ctx context.Context, tx pgx.Tx, typ, id, action, actor, note string) error {
	_, err := tx.Exec(ctx, `insert into moderation_log (target_type, target_id, action, actor, note)
		values ($1, $2, $3, $4, nullif($5, ''))`, typ, id, action, actor, note)
	return err
}

const appealCols = `a.id::text, i.kind::text, i.display, a.contact, a.reason, a.status::text, a.created_at,
	a.resolved_at, coalesce(a.resolved_by, ''), coalesce(a.note, '')`

func scanAppeal(row pgx.Row) (Appeal, error) {
	var a Appeal
	err := row.Scan(&a.ID, &a.Kind, &a.Display, &a.Contact, &a.Reason, &a.Status, &a.CreatedAt,
		&a.ResolvedAt, &a.ResolvedBy, &a.Note)
	return a, err
}

func (p *Postgres) CreateAppeal(ctx context.Context, na NewAppeal) (Appeal, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Appeal{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var indID string
	err = tx.QueryRow(ctx, `update indicators set status = 'disputed'
		where kind = $1 and value_hash = $2 and approved_count > 0 and status <> 'removed'
		returning id::text`, na.Indicator.Kind, na.Indicator.Hash).Scan(&indID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Appeal{}, ErrNotFound
	}
	if err != nil {
		return Appeal{}, err
	}
	var id string
	if err := tx.QueryRow(ctx, `insert into appeals (indicator_id, contact, reason, ip_hash)
		values ($1, $2, $3, nullif($4, '')) returning id::text`, indID, na.Contact, na.Reason, na.IPHash).Scan(&id); err != nil {
		return Appeal{}, err
	}
	a, err := scanAppeal(tx.QueryRow(ctx, `select `+appealCols+` from appeals a join indicators i on i.id = a.indicator_id
		where a.id = $1`, id))
	if err != nil {
		return Appeal{}, err
	}
	return a, tx.Commit(ctx)
}

func (p *Postgres) ListAppeals(ctx context.Context, status string, limit, offset int) ([]Appeal, error) {
	rows, err := p.pool.Query(ctx, `select `+appealCols+` from appeals a join indicators i on i.id = a.indicator_id
		where ($1 = '' or a.status::text = $1) order by a.created_at, a.id limit $2 offset $3`,
		status, clampLimit(limit), max(offset, 0))
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Appeal, error) { return scanAppeal(row) })
	if out == nil && err == nil {
		out = []Appeal{}
	}
	return out, err
}

func (p *Postgres) ResolveAppeal(ctx context.Context, id string, accept bool, actor, note string) (Appeal, error) {
	if !isUUID(id) {
		return Appeal{}, ErrNotFound
	}
	status, action := AppealRejected, "reject"
	if accept {
		status, action = AppealAccepted, "accept"
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Appeal{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var indID string
	err = tx.QueryRow(ctx, `update appeals set status = $2::appeal_status, resolved_at = now(), resolved_by = $3,
		note = nullif($4, '') where id = $1 and status = 'pending' returning indicator_id::text`,
		id, status, actor, note).Scan(&indID)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := tx.QueryRow(ctx, `select exists(select 1 from appeals where id = $1)`, id).Scan(&exists); err != nil {
			return Appeal{}, err
		}
		if !exists {
			return Appeal{}, ErrNotFound
		}
		return Appeal{}, ErrConflict
	}
	if err != nil {
		return Appeal{}, err
	}
	if accept {
		_, err = tx.Exec(ctx, `update indicators set status = 'removed' where id = $1`, indID)
	} else {
		_, err = tx.Exec(ctx, `update indicators set status = 'active' where id = $1 and status = 'disputed'
			and not exists (select 1 from appeals where indicator_id = $1 and status = 'pending')`, indID)
	}
	if err != nil {
		return Appeal{}, err
	}
	if err := logAction(ctx, tx, "appeal", id, action, actor, note); err != nil {
		return Appeal{}, err
	}
	a, err := scanAppeal(tx.QueryRow(ctx, `select `+appealCols+` from appeals a join indicators i on i.id = a.indicator_id
		where a.id = $1`, id))
	if err != nil {
		return Appeal{}, err
	}
	return a, tx.Commit(ctx)
}

func (p *Postgres) Stats(ctx context.Context) (Stats, error) {
	s := Stats{Indicators: map[string]int{}, Categories: map[string]int{}}
	err := p.pool.QueryRow(ctx, `select
		count(*) filter (where status = 'approved'),
		count(*) filter (where status = 'pending'),
		coalesce(sum(loss_amount) filter (where status = 'approved'), 0)
		from reports`).Scan(&s.ApprovedReports, &s.PendingReports, &s.TotalLoss)
	if err != nil {
		return s, err
	}
	rows, err := p.pool.Query(ctx, `select kind::text, count(*) from indicators
		where approved_count > 0 and status <> 'removed' group by kind`)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return s, err
		}
		s.Indicators[k] = n
	}
	rows.Close()
	rows, err = p.pool.Query(ctx, `select category, count(*) from reports where status = 'approved' group by category`)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return s, err
		}
		s.Categories[k] = n
	}
	return s, rows.Err()
}

func (p *Postgres) Blocklist(ctx context.Context, kind string) ([]string, error) {
	if kind != KindDomain && kind != KindAPK {
		return nil, fmt.Errorf("blocklist hanya untuk domain atau apk")
	}
	rows, err := p.pool.Query(ctx, `select value_hash from indicators
		where kind = $1 and approved_count > 0 and status <> 'removed' order by value_hash`, kind)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if out == nil && err == nil {
		out = []string{}
	}
	return out, err
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return false
			}
		}
	}
	return true
}

var (
	_ Store = (*Postgres)(nil)
	_ Store = (*Memory)(nil)
)
