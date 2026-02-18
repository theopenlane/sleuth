package scanner

import "sort"

var defaultInterestingSubdomainContexts = map[string]string{
	"admin":         "Administrative interface",
	"administrator": "Administrative interface",
	"api":           "API endpoint",
	"app":           "Application endpoint",
	"auth":          "Authentication service",
	"backup":        "Backup service",
	"bitbucket":     "Source control",
	"blog":          "Content service",
	"cdn":           "Content delivery endpoint",
	"cms":           "Content management system",
	"confluence":    "Documentation platform",
	"consul":        "Service discovery",
	"cpanel":        "Control panel",
	"dashboard":     "Operations dashboard",
	"db":            "Database service",
	"demo":          "Demo environment",
	"dev":           "Development environment",
	"docs":          "Documentation endpoint",
	"elastic":       "Search service",
	"ftp":           "File transfer service",
	"git":           "Source control",
	"github":        "Source control",
	"gitlab":        "Source control",
	"grafana":       "Metrics dashboard",
	"internal":      "Internal service",
	"jenkins":       "CI/CD service",
	"jira":          "Issue tracking service",
	"kibana":        "Log analysis",
	"mail":          "Email service",
	"manage":        "Management endpoint",
	"old":           "Legacy endpoint",
	"panel":         "Administration panel",
	"phpmyadmin":    "Database administration",
	"portal":        "Access portal",
	"private":       "Private endpoint",
	"prometheus":    "Monitoring service",
	"qa":            "QA environment",
	"redis":         "Caching service",
	"s3":            "Object storage endpoint",
	"staging":       "Staging environment",
	"stats":         "Analytics endpoint",
	"support":       "Support endpoint",
	"test":          "Testing environment",
	"vault":         "Secrets management",
	"vpn":           "VPN service",
	"wiki":          "Knowledge base",
}

func defaultInterestingSubdomainPatterns() []string {
	patterns := make([]string, 0, len(defaultInterestingSubdomainContexts))
	for pattern := range defaultInterestingSubdomainContexts {
		patterns = append(patterns, pattern)
	}

	sort.Strings(patterns)

	return patterns
}
