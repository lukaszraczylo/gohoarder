package pypi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type format int

const (
	formatHTML format = iota
	formatJSON
)

const (
	// contentTypeJSON is the PEP 691 media type of the JSON simple API.
	contentTypeJSON = "application/vnd.pypi.simple.v1+json"
	contentTypeHTML = "text/html; charset=UTF-8"

	// jsonPageVersion is the cache version of the upstream JSON page. It is on
	// the cache's metadata-entry list, so the page is never security-scanned.
	jsonPageVersion = "metadata"

	metadataSuffix = ".metadata"
)

// negotiateFormat picks the simple-API representation for an Accept header the
// way PyPI does: the highest q wins, JSON wins a tie, and a client that states
// no preference (or only wildcards) gets HTML. ok is false when the client
// accepts none of the supported types.
func negotiateFormat(accept string) (format, bool) {
	if strings.TrimSpace(accept) == "" {
		return formatHTML, true
	}

	bestQ := -1.0
	best := formatHTML
	for _, part := range strings.Split(accept, ",") {
		mediaType, q := parseMediaRange(part)
		if q <= 0 {
			continue
		}
		var candidate format
		switch mediaType {
		case "application/vnd.pypi.simple.v1+json", "application/vnd.pypi.simple.latest+json":
			candidate = formatJSON
		case "application/vnd.pypi.simple.v1+html", "application/vnd.pypi.simple.latest+html",
			"text/html", "text/*", "*/*":
			candidate = formatHTML
		default:
			continue
		}
		if q > bestQ || (q == bestQ && candidate == formatJSON) {
			bestQ, best = q, candidate
		}
	}
	return best, bestQ > 0
}

// parseMediaRange returns the lowercase media type and q-value of one Accept entry.
func parseMediaRange(entry string) (string, float64) {
	fields := strings.Split(entry, ";")
	mediaType := strings.ToLower(strings.TrimSpace(fields[0]))
	q := 1.0
	for _, param := range fields[1:] {
		name, value, found := strings.Cut(strings.TrimSpace(param), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
			continue
		}
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			q = parsed
		}
	}
	return mediaType, q
}

// rewriteJSONPage points every file URL of a PEP 691 page at the proxy. All
// other fields, including PEP 700 upload-time, pass through untouched.
func rewriteJSONPage(page []byte, packageName, pageURL, proxyBaseURL string) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(page, &doc); err != nil {
		return nil, fmt.Errorf("parse simple JSON page: %w", err)
	}
	rawFiles, ok := doc["files"]
	if !ok {
		return page, nil
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(rawFiles, &files); err != nil {
		return nil, fmt.Errorf("parse simple JSON files: %w", err)
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("parse page URL: %w", err)
	}

	for _, file := range files {
		var filename, fileURL string
		if json.Unmarshal(file["filename"], &filename) != nil || filename == "" {
			continue
		}
		if json.Unmarshal(file["url"], &fileURL) != nil || fileURL == "" {
			continue
		}
		original := fileURL
		if ref, parseErr := url.Parse(fileURL); parseErr == nil {
			original = base.ResolveReference(ref).String()
		}
		proxied := fmt.Sprintf("%s/%s/%s?original_url=%s", proxyBaseURL, packageName, url.PathEscape(filename), url.QueryEscape(original))
		encoded, marshalErr := json.Marshal(proxied)
		if marshalErr != nil {
			return nil, fmt.Errorf("encode file url: %w", marshalErr)
		}
		file["url"] = encoded
	}

	rewrittenFiles, err := json.Marshal(files)
	if err != nil {
		return nil, fmt.Errorf("encode simple JSON files: %w", err)
	}
	doc["files"] = rewrittenFiles
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode simple JSON page: %w", err)
	}
	return out, nil
}
