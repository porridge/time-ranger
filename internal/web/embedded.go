package web

import (
	"embed"
)

// StaticFS is the embedded filesystem containing the web dashboard.
//
//go:embed index.html
var StaticFS embed.FS
