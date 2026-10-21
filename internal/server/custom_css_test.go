// SPDX-FileCopyrightText: 2026 Authelia
// SPDX-FileCopyrightText: 2026 authelia-plus contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/templates"
)

const (
	testCustomCSS     = "body { background: #123456; }\n"
	testMainCSSLink   = `<link rel="stylesheet" crossorigin href="./static/css/index.css">`
	testCustomCSSLink = `<link rel="stylesheet" href="./static/custom.css?v=`
)

// ReadFileCustomCSSIndex substitutes a portal index shaped like the one vite builds: the portal's stylesheet in the
// head, and the VITE_CUSTOM_CSS value from web/.env.production at the top of the body.
type ReadFileCustomCSSIndex struct {
	index string
}

func (lfs *ReadFileCustomCSSIndex) Open(name string) (fs.File, error) {
	return assets.Open(name)
}

func (lfs *ReadFileCustomCSSIndex) ReadFile(name string) ([]byte, error) {
	switch name {
	case "public_html/index.html":
		return []byte(lfs.index), nil
	default:
		return assets.ReadFile(name)
	}
}

func newCustomCSSIndex(t *testing.T) *ReadFileCustomCSSIndex {
	file, err := os.Open("../../web/.env.production")
	require.NoError(t, err)

	defer file.Close()

	var value string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if v, ok := strings.CutPrefix(scanner.Text(), "VITE_CUSTOM_CSS="); ok {
			value = strings.Trim(v, "'")
		}
	}

	require.NoError(t, scanner.Err())
	require.NotEmpty(t, value)

	// Vite drops the vite-ignore attribute when it builds the index.
	value = strings.Replace(value, " vite-ignore", "", 1)

	return &ReadFileCustomCSSIndex{
		index: `<!doctype html>
<html lang="{{ .Language }}">
    <head>
        <meta property="csp-nonce" content="{{ .CSPNonce }}" />
        ` + testMainCSSLink + `
    </head>
    <body data-theme="{{ .Theme }}">
        ` + value + `
        <div id="root"></div>
    </body>
</html>`,
	}
}

func newCustomCSSTestHandler(t *testing.T, assetPath string) fasthttp.RequestHandler {
	provider, err := templates.New(templates.Config{})
	require.NoError(t, err)

	require.NoError(t, provider.LoadTemplatedAssets(newCustomCSSIndex(t)))

	providers := middlewares.NewProvidersBasic()
	providers.Templates = provider

	config := &schema.Configuration{
		Server: schema.Server{
			Address:   schema.DefaultServerConfiguration.Address,
			Endpoints: schema.DefaultServerConfiguration.Endpoints,
			AssetPath: assetPath,
		},
	}

	handler, err := handlerMain(config, providers)
	require.NoError(t, err)

	return handler
}

func doCustomCSSRequest(handler fasthttp.RequestHandler, method, uri string) *fasthttp.RequestCtx {
	ctx := newAssetRequestCtx(method, uri, "")

	ctx.Request.Header.Set(fasthttp.HeaderXForwardedProto, "https")
	ctx.Request.Header.Set(fasthttp.HeaderXForwardedHost, "auth.example.com")

	handler(ctx)

	return ctx
}

func TestCustomCSSShouldBeLinkedAndServedWhenPresent(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, fileCustomCSS), []byte(testCustomCSS), 0o600))

	handler := newCustomCSSTestHandler(t, dir)

	sum := sha256.Sum256([]byte(testCustomCSS))
	version := hex.EncodeToString(sum[:])[:lenCustomCSSVersion]

	ctx := doCustomCSSRequest(handler, fasthttp.MethodGet, "/")
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	body := string(ctx.Response.Body())

	assert.Contains(t, body, testCustomCSSLink+version+`"`)
	assert.Equal(t, 1, strings.Count(body, "custom.css"))

	main, custom := strings.Index(body, testMainCSSLink), strings.Index(body, testCustomCSSLink)
	require.NotEqual(t, -1, main)
	require.NotEqual(t, -1, custom)
	assert.Less(t, main, custom, "custom.css must come after the portal's stylesheet so its rules win")

	assert.NotContains(t, body, "<style")
	assert.NotContains(t, string(ctx.Response.Header.Peek(fasthttp.HeaderContentSecurityPolicy)), "custom.css")

	for _, method := range []string{fasthttp.MethodGet, fasthttp.MethodHead} {
		t.Run(method, func(t *testing.T) {
			ctx := doCustomCSSRequest(handler, method, "/static/custom.css")

			assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
			assert.Equal(t, "text/css; charset=utf-8", string(ctx.Response.Header.ContentType()))
			assert.Equal(t, "nosniff", string(ctx.Response.Header.Peek(fasthttp.HeaderXContentTypeOptions)))

			if method == fasthttp.MethodGet {
				assert.Equal(t, testCustomCSS, string(ctx.Response.Body()))
			}
		})
	}
}

func TestCustomCSSShouldNotBeLinkedWhenAbsent(t *testing.T) {
	testCases := []struct {
		name      string
		assetPath string
	}{
		{"ShouldNotLinkWithoutAssetPath", ""},
		{"ShouldNotLinkWithoutFile", t.TempDir()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := newCustomCSSTestHandler(t, tc.assetPath)

			ctx := doCustomCSSRequest(handler, fasthttp.MethodGet, "/")
			require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

			body := string(ctx.Response.Body())

			assert.Contains(t, body, testMainCSSLink)
			assert.NotContains(t, body, "custom.css")

			ctx = doCustomCSSRequest(handler, fasthttp.MethodGet, "/static/custom.css")
			assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
		})
	}
}

func TestCustomCSSShouldNotServeADirectory(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dir, fileCustomCSS), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, fileCustomCSS, "index.html"), []byte("<b>listing</b>"), 0o600))

	handler := newCustomCSSTestHandler(t, dir)

	ctx := doCustomCSSRequest(handler, fasthttp.MethodGet, "/")
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.NotContains(t, string(ctx.Response.Body()), "custom.css")

	for _, method := range []string{fasthttp.MethodGet, fasthttp.MethodHead} {
		t.Run(method, func(t *testing.T) {
			ctx := doCustomCSSRequest(handler, method, "/static/custom.css")

			assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
			assert.NotContains(t, string(ctx.Response.Header.ContentType()), "text/html")
			assert.NotContains(t, string(ctx.Response.Body()), "listing")
		})
	}
}

func TestCustomCSSShouldOnlyServeTheFixedFile(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, fileCustomCSS), []byte(testCustomCSS), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.css"), []byte(testCustomCSS), 0o600))

	handler := newCustomCSSTestHandler(t, dir)

	for _, uri := range []string{"/static/other.css", "/static/custom.css/../other.css", "/static/%2e%2e/custom.css"} {
		t.Run(uri, func(t *testing.T) {
			ctx := doCustomCSSRequest(handler, fasthttp.MethodGet, uri)

			assert.NotEqual(t, testCustomCSS, string(ctx.Response.Body()))
		})
	}
}

func TestGetCustomCSSVersion(t *testing.T) {
	dir := t.TempDir()

	assert.Empty(t, getCustomCSSVersion(""))
	assert.Empty(t, getCustomCSSVersion(dir))

	require.NoError(t, os.WriteFile(filepath.Join(dir, fileCustomCSS), []byte(testCustomCSS), 0o600))

	first := getCustomCSSVersion(dir)
	assert.Len(t, first, lenCustomCSSVersion)

	require.NoError(t, os.WriteFile(filepath.Join(dir, fileCustomCSS), []byte(testCustomCSS+"a { color: red; }\n"), 0o600))

	assert.NotEqual(t, first, getCustomCSSVersion(dir))
}
