package main

import (
	"net/url"
	"strings"
)

// isFontInURL checks that web-font is requested in URL.
func isFontInURL(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}

	value := strings.ToLower(u.Path)

	switch {
	case strings.HasSuffix(value, ".eot"):
		return true
	case strings.HasSuffix(value, ".otf"):
		return true
	case strings.HasSuffix(value, ".svg"):
		return true
	case strings.HasSuffix(value, ".ttf"):
		return true
	case strings.HasSuffix(value, ".woff"):
		return true
	case strings.HasSuffix(value, ".woff2"):
		return true
	}

	return false
}
