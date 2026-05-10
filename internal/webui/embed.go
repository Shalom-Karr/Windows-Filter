// Package webui embeds the dashboard SPA assets.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed dist
var distFS embed.FS

// FS returns a sub-filesystem rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

// ReadFile reads a file from dist/ by its relative path (e.g. "index.html").
func ReadFile(name string) ([]byte, error) {
	return distFS.ReadFile("dist/" + name)
}
