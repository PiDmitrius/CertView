package web

import "embed"

//go:embed index.html logo.svg
var Static embed.FS
