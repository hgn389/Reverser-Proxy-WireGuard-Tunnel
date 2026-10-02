package webassets

import "embed"

// Files contains the self-contained web panel templates and styles.
//
//go:embed templates/*.html static/*
var Files embed.FS
