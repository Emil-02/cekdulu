-- cekdulu: skema awal laporan penipuan.
--
-- Prinsip privasi:
--   * Nomor HP & rekening hanya disimpan sebagai HMAC (value_hash) + versi tersamar (display).
--   * Domain & hash APK disimpan apa adanya karena bukan data pribadi.
--   * Semua tabel memakai RLS tanpa policy untuk anon/authenticated, sehingga hanya
--     server API (koneksi Postgres langsung / service role) yang bisa membaca & menulis.
--   * Data publik hanya lewat view public_indicators (laporan yang sudah disetujui).

create extension if not exists pgcrypto;

create type indicator_kind as enum ('domain', 'apk', 'phone', 'account');
create type indicator_status as enum ('active', 'disputed', 'removed');
create type report_status as enum ('pending', 'approved', 'rejected');
create type appeal_status as enum ('pending', 'accepted', 'rejected');

create table indicators (
  id             uuid primary key default gen_random_uuid(),
  kind           indicator_kind not null,
  value_hash     text not null,
  display        text not null,
  approved_count integer not null default 0 check (approved_count >= 0),
  status         indicator_status not null default 'active',
  first_seen     timestamptz not null default now(),
  last_seen      timestamptz not null default now(),
  unique (kind, value_hash)
);

create table reports (
  id            uuid primary key default gen_random_uuid(),
  indicator_id  uuid not null references indicators(id) on delete cascade,
  category      text not null,
  description   text not null check (char_length(description) between 20 and 2000),
  loss_amount   bigint check (loss_amount is null or loss_amount >= 0),
  status        report_status not null default 'pending',
  contact_hash  text,
  ip_hash       text,
  created_at    timestamptz not null default now(),
  reviewed_at   timestamptz,
  reviewed_by   text,
  review_note   text
);
create index reports_status_created_idx on reports (status, created_at);
create index reports_indicator_idx on reports (indicator_id);
create index reports_contact_idx on reports (contact_hash, created_at) where contact_hash is not null;
create index reports_ip_idx on reports (ip_hash, created_at) where ip_hash is not null;

create table evidence (
  id           uuid primary key default gen_random_uuid(),
  report_id    uuid not null references reports(id) on delete cascade,
  storage_key  text not null,
  sha256       text not null,
  mime         text not null,
  size         bigint not null check (size > 0),
  created_at   timestamptz not null default now()
);
create index evidence_report_idx on evidence (report_id);

create table appeals (
  id            uuid primary key default gen_random_uuid(),
  indicator_id  uuid not null references indicators(id) on delete cascade,
  contact       text not null,
  reason        text not null check (char_length(reason) between 20 and 2000),
  status        appeal_status not null default 'pending',
  ip_hash       text,
  created_at    timestamptz not null default now(),
  resolved_at   timestamptz,
  resolved_by   text,
  note          text
);
create index appeals_status_created_idx on appeals (status, created_at);

-- Jejak audit setiap keputusan moderator.
create table moderation_log (
  id           bigint generated always as identity primary key,
  target_type  text not null check (target_type in ('report', 'appeal')),
  target_id    uuid not null,
  action       text not null,
  actor        text not null,
  note         text,
  created_at   timestamptz not null default now()
);

alter table indicators enable row level security;
alter table reports enable row level security;
alter table evidence enable row level security;
alter table appeals enable row level security;
alter table moderation_log enable row level security;

-- View publik: hanya indikator dengan laporan tersetujui dan tidak dihapus.
create view public_indicators with (security_invoker = false) as
select kind, display, approved_count, status, first_seen, last_seen
from indicators
where approved_count > 0 and status <> 'removed';

revoke all on public_indicators from public;
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'grant select on public_indicators to anon, authenticated';
  end if;
end $$;
