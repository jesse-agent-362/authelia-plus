// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

// authelia-plus: an operator stylesheet. A file named custom.css in server.asset_path is served at the fixed path
// /static/custom.css, and the portal links to it after its own stylesheet.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/middlewares"
)

const (
	fileCustomCSS = "custom.css"

	// The custom.css link's cache busting value is this many hex characters of the file's SHA-256.
	lenCustomCSSVersion = 16
)

// newCustomCSSHandler serves custom.css from the asset path with nosniff, and falls back to next when there is no such
// regular file. A directory named custom.css falls back too, as the file server would answer it with an HTML index. The
// content type comes from the .css extension, as text/css.
func newCustomCSSHandler(root string, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	if root == "" {
		return next
	}

	handler := middlewares.AssetOverride(root, 1, next)
	asset := filepath.Join(root, fileCustomCSS)

	return func(ctx *fasthttp.RequestCtx) {
		middlewares.SetBaseSecurityHeaders(ctx)

		if info, err := os.Stat(asset); err != nil || !info.Mode().IsRegular() {
			next(ctx)

			return
		}

		handler(ctx)
	}
}

// getCustomCSSVersion returns the cache busting value for the custom.css link, or an empty string when there is no
// custom.css in the asset path, in which case the portal doesn't link to it. It's read once at startup, so a changed
// custom.css takes effect on restart.
func getCustomCSSVersion(root string) string {
	if root == "" {
		return ""
	}

	data, err := os.ReadFile(filepath.Join(root, fileCustomCSS))
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])[:lenCustomCSSVersion]
}
