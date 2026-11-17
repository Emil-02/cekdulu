// Package rules embeds the default detection rules and reference data so the
// CLI and API work out of the box. Edit the YAML files to change behaviour.
package rules

import "embed"

// FS holds rules (*.yaml at the root) and reference data (data/*.yaml).
//
//go:embed *.yaml data/*.yaml
var FS embed.FS
