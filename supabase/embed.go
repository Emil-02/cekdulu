// Package supabase embeds the SQL migrations so the API server can apply
// them on start-up (CEKDULU_MIGRATE=1) without the Supabase CLI.
package supabase

import "embed"

// Migrations holds migrations/*.sql, applied in lexical order.
//
//go:embed migrations/*.sql
var Migrations embed.FS
