package main

import (
	"regexp"
	"strings"
)

const masked = "‹hidden›"

// Best-effort masking of secrets in command lines and log text, applied before anything is stored.
var secretPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// dscl . -passwd /Users/name [old] new
	{regexp.MustCompile(`(?i)(-passwd\s+\S+)\s+.*$`), "${1} " + masked},
	// security unlock-keychain -p secret, security add-generic-password ... -w secret
	{regexp.MustCompile(`(\bsecurity\b.*?\s-[pw])\s+\S+`), "${1} " + masked},
	// -password secret, --adminPassword=secret, --api-key secret
	{regexp.MustCompile(`(?i)(^|\s)(-{1,2}[a-z_-]*(?:password|passwd|secret|token|api-?key|api_key|credential))(=|\s+)([^/\s]\S*)`), "${1}${2}${3}" + masked},
	// password=secret, client_secret: secret
	{regexp.MustCompile(`(?i)\b([a-z_]*(?:password|passwd|secret|token|apikey|api_key|access_key|credential)[a-z_]*)(\s*[=:]\s*)([^\s&"']+)`), "${1}${2}" + masked},
	// HTTP authorization headers and bearer tokens
	{regexp.MustCompile(`(?i)(authorization:\s*)(?:(?:bearer|basic|token)\s+)?\S+`), "${1}" + masked},
	{regexp.MustCompile(`(?i)\b(bearer\s+)\S+`), "${1}" + masked},
	// user:password@ in URLs
	{regexp.MustCompile(`(://[^/\s:@]+:)[^@\s/]+@`), "${1}" + masked + "@"},
}

// Long opaque strings with letters and digits are usually keys, tokens or JWTs.
var opaqueRe = regexp.MustCompile(`[A-Za-z0-9_+-]{40,}={0,2}`)

var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|apikey|api_key|privatekey|private_key|challenge|credential|pin)$`)

func redact(s string) string {
	for _, p := range secretPatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return opaqueRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsAny(m, "0123456789") && strings.IndexFunc(m, isLetter) >= 0 {
			return masked
		}
		return m
	})
}

func isLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// isSecretKey reports whether a settings key (the last part of a "a.b.c" path) names a secret.
func isSecretKey(path string) bool {
	if i := strings.LastIndexAny(path, ".]"); i >= 0 {
		path = path[i+1:]
	}
	return secretKeyRe.MatchString(path)
}
