package middleware

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/artalkjs/artalk/v2/internal/core"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func getCorsAllowOrigins(app *core.App) []string {
	allowURLs := []string{}
	allowURLs = append(allowURLs, app.Conf().TrustedDomains...) // 导入配置中的可信域名
	for _, site := range app.Dao().FindAllSitesCooked() {       // 导入数据库中的站点 urls
		allowURLs = append(allowURLs, site.Urls...)
	}

	allowOrigins := []string{}
	for _, u := range allowURLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}

		urlP, err := url.Parse(u)
		if err != nil || urlP.Scheme == "" || urlP.Host == "" {
			continue
		}

		allowOrigins = append(allowOrigins, fmt.Sprintf("%s://%s", urlP.Scheme, urlP.Host))
	}

	return allowOrigins
}

func CheckOriginTrusted(app *core.App, origin string) bool {
	for _, allowed := range getCorsAllowOrigins(app) {
		if allowed == origin {
			return true
		}
		// Support wildcard subdomain matching (e.g. "https://*.example.com")
		if matchWildcardOrigin(allowed, origin) {
			return true
		}
	}
	return false
}

// matchWildcardOrigin checks if origin matches a wildcard pattern like "https://*.example.com".
// Supports multi-level wildcards (e.g. "*.example.com" matches "a.b.example.com")
// and multiple wildcards (e.g. "*.*.edu.mx" matches "a.b.edu.mx").
func matchWildcardOrigin(pattern, origin string) bool {
	patternScheme, patternHost, patternPort, ok := splitOrigin(pattern)
	if !ok {
		return false
	}

	originScheme, originHost, originPort, ok := splitOrigin(origin)
	if !ok {
		return false
	}

	// Schemes must match
	if patternScheme != originScheme {
		return false
	}

	// Ports must match (normalize default ports)
	if normalizePort(patternPort, patternScheme) != normalizePort(originPort, originScheme) {
		return false
	}

	// No wildcard in pattern; let CheckOriginTrusted handle exact matches
	if !strings.Contains(patternHost, "*") {
		return false
	}

	return matchWildcardHost(patternHost, originHost)
}

// splitOrigin splits an origin string into scheme, host, and port.
// It handles both IPv4/IPv6 hosts. IPv6 addresses are returned with brackets.
func splitOrigin(s string) (scheme, host, port string, ok bool) {
	schemeEnd := strings.Index(s, "://")
	if schemeEnd == -1 {
		return "", "", "", false
	}
	scheme = s[:schemeEnd]
	rest := s[schemeEnd+3:]

	// Extract port
	if strings.HasPrefix(rest, "[") {
		// IPv6 address
		bracketEnd := strings.Index(rest, "]")
		if bracketEnd == -1 {
			return "", "", "", false
		}
		host = rest[:bracketEnd+1]
		if bracketEnd+1 < len(rest) && rest[bracketEnd+1] == ':' {
			port = rest[bracketEnd+2:]
		}
	} else {
		if colonIdx := strings.LastIndex(rest, ":"); colonIdx != -1 {
			host = rest[:colonIdx]
			port = rest[colonIdx+1:]
		} else {
			host = rest
		}
	}

	return scheme, host, port, true
}

func normalizePort(port, scheme string) string {
	if port != "" {
		return port
	}
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return port
	}
}

// matchWildcardHost matches a host pattern against a host.
// The pattern may contain '*' as a wildcard label at the beginning.
// Each '*' matches one or more labels.
func matchWildcardHost(patternHost, originHost string) bool {
	pLabels := strings.Split(patternHost, ".")
	oLabels := strings.Split(originHost, ".")

	// Match exact suffix labels from the right
	suffixLen := 0
	for i := 1; i <= len(pLabels) && i <= len(oLabels); i++ {
		pIdx := len(pLabels) - i
		if pLabels[pIdx] == "*" {
			break
		}
		if pLabels[pIdx] != oLabels[len(oLabels)-i] {
			return false
		}
		suffixLen++
	}

	// The remaining prefix of the pattern must be all wildcards
	prefixWildcards := len(pLabels) - suffixLen
	for i := 0; i < prefixWildcards; i++ {
		if pLabels[i] != "*" {
			return false
		}
	}

	// Each wildcard must match at least one origin label
	return len(oLabels)-suffixLen >= prefixWildcards
}

func CheckURLTrusted(app *core.App, targetUrl string) (trusted bool, origin string, err error) {
	u, err := url.Parse(targetUrl)
	if err != nil {
		return false, "", fmt.Errorf("invalid URL")
	}
	origin = u.Scheme + "://" + u.Host
	trusted = CheckOriginTrusted(app, origin)
	return trusted, origin, nil
}

func CorsMiddleware(app *core.App) func(*fiber.Ctx) error {
	return cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			return CheckOriginTrusted(app, origin)
		},
	})
}
