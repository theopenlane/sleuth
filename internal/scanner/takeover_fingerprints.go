package scanner

// TakeoverFingerprint defines a subdomain takeover service fingerprint.
// This structure contains patterns and fingerprints for detecting potential
// subdomain takeover vulnerabilities.
type TakeoverFingerprint struct {
	Service      string   // Service name (e.g., "AWS S3", "Heroku")
	CNAMEPattern string   // CNAME pattern to match (e.g., ".herokuapp.com")
	Fingerprints []string // HTTP response fingerprints indicating vulnerability
	Vulnerable   bool     // Whether this service is currently vulnerable
	NXDomain     bool     // Whether NXDOMAIN alone indicates vulnerability
}

// takeoverFingerprints contains service definitions based on can-i-take-over-xyz.
// Source: https://github.com/EdOverflow/can-i-take-over-xyz
//
// This list is maintained to help identify potential subdomain takeover vulnerabilities
// where a subdomain CNAME points to an external service that is unclaimed or deleted.
var takeoverFingerprints = []TakeoverFingerprint{
	{
		Service:      "AWS Elastic Beanstalk",
		CNAMEPattern: ".elasticbeanstalk.com",
		Fingerprints: []string{},
		Vulnerable:   true,
		NXDomain:     true,
	},
	{
		Service:      "AWS S3",
		CNAMEPattern: ".s3.amazonaws.com",
		Fingerprints: []string{"The specified bucket does not exist", "NoSuchBucket"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "AWS S3 Website",
		CNAMEPattern: ".s3-website",
		Fingerprints: []string{"The specified bucket does not exist", "NoSuchBucket"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Azure",
		CNAMEPattern: ".cloudapp.azure.com",
		Fingerprints: []string{},
		Vulnerable:   true,
		NXDomain:     true,
	},
	{
		Service:      "Azure",
		CNAMEPattern: ".cloudapp.net",
		Fingerprints: []string{},
		Vulnerable:   true,
		NXDomain:     true,
	},
	{
		Service:      "Azure",
		CNAMEPattern: ".azurewebsites.net",
		Fingerprints: []string{},
		Vulnerable:   true,
		NXDomain:     true,
	},
	{
		Service:      "Bitbucket",
		CNAMEPattern: ".bitbucket.io",
		Fingerprints: []string{"Repository not found"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Cargo Collective",
		CNAMEPattern: ".cargocollective.com",
		Fingerprints: []string{"404 Not Found"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Desk",
		CNAMEPattern: ".desk.com",
		Fingerprints: []string{"Please try again or try Desk.com free for 14 days.", "Sorry, We Couldn't Find That Page"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Fastly",
		CNAMEPattern: ".fastly.net",
		Fingerprints: []string{"Fastly error: unknown domain"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Feedpress",
		CNAMEPattern: ".feedpress.me",
		Fingerprints: []string{"The feed has not been found."},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Ghost",
		CNAMEPattern: ".ghost.io",
		Fingerprints: []string{"The thing you were looking for is no longer here"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "GitHub Pages",
		CNAMEPattern: ".github.io",
		Fingerprints: []string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "GitLab Pages",
		CNAMEPattern: ".gitlab.io",
		Fingerprints: []string{"The page you're looking for could not be found"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "HatenaBlog",
		CNAMEPattern: ".hatenablog.com",
		Fingerprints: []string{"404 Blog is not found"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Help Juice",
		CNAMEPattern: ".helpjuice.com",
		Fingerprints: []string{"We could not find what you're looking for."},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Help Scout",
		CNAMEPattern: ".helpscoutdocs.com",
		Fingerprints: []string{"No settings were found for this company:"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Heroku",
		CNAMEPattern: ".herokuapp.com",
		Fingerprints: []string{"No such app", "There's nothing here, yet."},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Pantheon",
		CNAMEPattern: ".pantheonsite.io",
		Fingerprints: []string{"404 error unknown site!"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Shopify",
		CNAMEPattern: ".myshopify.com",
		Fingerprints: []string{"Sorry, this shop is currently unavailable.", "Only one step left!"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Statuspage",
		CNAMEPattern: ".statuspage.io",
		Fingerprints: []string{"You are being <a href=\"https://www.statuspage.io\">redirected"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Surge.sh",
		CNAMEPattern: ".surge.sh",
		Fingerprints: []string{"project not found"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Tumblr",
		CNAMEPattern: ".tumblr.com",
		Fingerprints: []string{"Whatever you were looking for doesn't currently exist at this address"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Tilda",
		CNAMEPattern: ".tilda.ws",
		Fingerprints: []string{"Please renew your subscription"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "UserVoice",
		CNAMEPattern: ".uservoice.com",
		Fingerprints: []string{"This UserVoice subdomain is currently available!"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Webflow",
		CNAMEPattern: ".webflow.io",
		Fingerprints: []string{"<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Wordpress",
		CNAMEPattern: ".wordpress.com",
		Fingerprints: []string{"Do you want to register"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "WP Engine",
		CNAMEPattern: ".wpengine.com",
		Fingerprints: []string{},
		Vulnerable:   true,
		NXDomain:     true,
	},
	{
		Service:      "Zendesk",
		CNAMEPattern: ".zendesk.com",
		Fingerprints: []string{"Help Center Closed", "<title>No Help Center Here</title>"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Uberflip",
		CNAMEPattern: ".uberflip.com",
		Fingerprints: []string{"Non-hub domain, The URL you've accessed does not provide a hub."},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Unbounce",
		CNAMEPattern: ".unbouncepages.com",
		Fingerprints: []string{"The requested URL was not found on this server."},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Smartling",
		CNAMEPattern: ".smartling.com",
		Fingerprints: []string{"Domain is not configured"},
		Vulnerable:   true,
		NXDomain:     false,
	},
	{
		Service:      "Kinsta",
		CNAMEPattern: ".kinsta.cloud",
		Fingerprints: []string{"No Site For Domain"},
		Vulnerable:   true,
		NXDomain:     false,
	},
}
