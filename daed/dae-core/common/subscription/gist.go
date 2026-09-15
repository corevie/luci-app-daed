/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * GitHub Gist subscription source. Supports pulling a single file (e.g.
 * the cfMac nodes.json node library) out of a gist, private or public:
 *
 *	gist://<gistID>                    public gist, auto-pick a file
 *	gist://<gistID>/<filename>         public gist, specific file
 *	gist://<token>@<gistID>            private gist (token: gist scope)
 *	gist://<token>@<gistID>/<filename> private gist, specific file
 *	gist-file://...                    like gist:// but persists the
 *	                                   response to persist.d/<tag>.sub
 *	                                   as a fallback (same as http-file)
 *
 * Plain https://gist.github.com/<id> URLs are NOT redirected here (they
 * would return HTML); use the gist:// form.
 */

package subscription

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const gistAPIBase = "https://api.github.com"

type gistObject struct {
	ID        string              `json:"id"`
	HTMLURL   string              `json:"html_url"`
	UpdatedAt string              `json:"updated_at"`
	Files     map[string]gistFile `json:"files"`
}

type gistFile struct {
	Filename  string  `json:"filename"`
	RawURL    string  `json:"raw_url"`
	Size      int     `json:"size"`
	Truncated *bool   `json:"truncated"`
	Content   *string `json:"content"`
}

// GistRef identifies the target of a gist:// subscription URL.
type GistRef struct {
	Token    string
	GistID   string
	Filename string
}

// ParseGistURL parses gist://[token@]gistID[/filename].
//
// Note url.Parse maps "gist://token@id/file" to User=token, Host=id,
// Path=/file, so userinfo carries the optional token.
func ParseGistURL(u *url.URL) (ref GistRef, err error) {
	if u.User != nil {
		ref.Token = u.User.Username()
	}
	ref.GistID = strings.TrimSpace(u.Host)
	if ref.GistID == "" {
		// Opaque form "gist:id" (no authority) is tolerated too.
		ref.GistID = strings.TrimSpace(strings.TrimPrefix(u.Opaque, "//"))
	}
	if ref.GistID == "" {
		return ref, fmt.Errorf("gist reference has no gist ID")
	}
	ref.Filename = strings.TrimSpace(strings.Trim(u.Path, "/"))
	if idx := strings.IndexByte(ref.GistID, '@'); idx >= 0 {
		// "gist://token@id" keeps everything opaque in some parsers.
		ref.Token, ref.GistID = ref.GistID[:idx], ref.GistID[idx+1:]
	}
	return ref, nil
}

// looksLikeGistURL reports whether the URL points at a gist (gist://
// scheme or an api.github.com/gists/<id> endpoint).
func looksLikeGistURL(u *url.URL) bool {
	return u.Scheme == "gist" || u.Scheme == "gist-file" ||
		(u.Host == "api.github.com" && strings.HasPrefix(u.Path, "/gists/"))
}

// FetchGist downloads the requested file content from a gist.
//
// When filename is empty, the first *.json file (or, failing that, the
// first file) of the gist is picked — nodes.json libraries typically are
// the only JSON file in their gist.
func FetchGist(client *http.Client, token, gistID, filename string) (content []byte, pickedName string, err error) {
	apiURL := gistAPIBase + "/gists/" + url.PathEscape(gistID)
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("gist api request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("gist api returned %v: %.200s", resp.StatusCode, string(body))
	}
	var g gistObject
	if err = json.Unmarshal(body, &g); err != nil {
		return nil, "", fmt.Errorf("failed to parse gist api response: %w", err)
	}

	file := pickGistFile(&g, filename)
	if file == nil {
		return nil, "", fmt.Errorf("gist %v has no file %q", gistID, filename)
	}
	// Inline content is present for small files; otherwise fetch raw_url.
	if file.Content != nil && *file.Content != "" {
		return []byte(*file.Content), file.Filename, nil
	}
	if file.RawURL == "" {
		return nil, "", fmt.Errorf("gist file %q has neither content nor raw_url", file.Filename)
	}
	rawReq, err := http.NewRequest(http.MethodGet, file.RawURL, nil)
	if err != nil {
		return nil, "", err
	}
	if token != "" {
		// raw.githubusercontent.com accepts the same bearer token.
		rawReq.Header.Set("Authorization", "Bearer "+token)
	}
	rawResp, err := client.Do(rawReq)
	if err != nil {
		return nil, "", fmt.Errorf("gist raw download failed: %w", err)
	}
	defer func() { _ = rawResp.Body.Close() }()
	if rawResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("gist raw download returned %v", rawResp.StatusCode)
	}
	content, err = io.ReadAll(io.LimitReader(rawResp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", err
	}
	return content, file.Filename, nil
}

// pickGistFile selects the wanted file, falling back to the first *.json
// file, then any file.
func pickGistFile(g *gistObject, filename string) *gistFile {
	if filename != "" {
		if f, ok := g.Files[filename]; ok {
			return &f
		}
		return nil
	}
	// Prefer nodes.json, then any .json, then anything.
	if f, ok := g.Files["nodes.json"]; ok {
		return &f
	}
	var fallback *gistFile
	for name, f := range g.Files {
		fCopy := f
		if strings.HasSuffix(name, ".json") {
			return &fCopy
		}
		if fallback == nil {
			fallback = &fCopy
		}
	}
	return fallback
}
