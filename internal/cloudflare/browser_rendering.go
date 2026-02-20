package cloudflare

import (
	"context"
	"fmt"
	"net/http"

	"github.com/theopenlane/httpsling"
)

const (
	// browserRenderingPath is the API path for the browser rendering JSON endpoint
	browserRenderingPath = "browser-rendering/json"
	// schemaName is the identifier for the company profile JSON schema
	schemaName = "company_profile"
)

// CompanyProfile holds structured company information extracted from a website
type CompanyProfile struct {
	// Name is the company name
	Name string `json:"name"`
	// Description is a brief description of what the company does
	Description string `json:"description"`
	// Industry is the primary industry the company operates in
	Industry string `json:"industry"`
	// Products is a list of key products or services
	Products []string `json:"products"`
	// Location is the headquarters location
	Location string `json:"location"`
	// EmployeeRange is the approximate employee count range
	EmployeeRange string `json:"employee_range"`
	// FoundedYear is the year the company was founded, if discoverable
	FoundedYear string `json:"founded_year"`
	// EstimatedRevenue is the estimated annual revenue range, if discoverable
	EstimatedRevenue string `json:"estimated_revenue"`
	// SocialLinks holds URLs for the company's social media profiles
	SocialLinks SocialLinks `json:"social_links"`
	// Technologies lists third-party SaaS tools and technology vendors detected on the website
	Technologies []string `json:"technologies"`
}

// SocialLinks holds URLs for the company's social media and community profiles
type SocialLinks struct {
	// LinkedIn is the company's LinkedIn profile URL
	LinkedIn string `json:"linkedin,omitempty"`
	// Twitter is the company's Twitter/X profile URL
	Twitter string `json:"twitter,omitempty"`
	// GitHub is the company's GitHub organization URL
	GitHub string `json:"github,omitempty"`
	// Discord is the company's Discord invite or server URL
	Discord string `json:"discord,omitempty"`
	// Instagram is the company's Instagram profile URL
	Instagram string `json:"instagram,omitempty"`
	// YouTube is the company's YouTube channel URL
	YouTube string `json:"youtube,omitempty"`
	// Facebook is the company's Facebook page URL
	Facebook string `json:"facebook,omitempty"`
}

// browserRenderingRequest is the request body for the browser rendering API
type browserRenderingRequest struct {
	URL             string         `json:"url"`
	ResponseFormat  responseFormat `json:"response_format"`
	GotoOptions     *gotoOptions   `json:"gotoOptions,omitempty"`
	WaitForSelector string         `json:"waitForSelector,omitempty"`
}

// gotoOptions controls page navigation behavior in the browser rendering API
type gotoOptions struct {
	// WaitUntil controls when navigation is considered complete.
	// Use "networkidle2" for JavaScript SPAs that load content asynchronously.
	WaitUntil string `json:"waitUntil,omitempty"`
	// Timeout is the navigation timeout in milliseconds. Defaults to 30000 (30s)
	// in Puppeteer. Set higher for heavy SPAs that take longer to reach network idle.
	Timeout int `json:"timeout,omitempty"`
}

// responseFormat specifies JSON schema extraction
type responseFormat struct {
	Type       string               `json:"type"`
	JSONSchema jsonSchemaDefinition `json:"json_schema"`
}

// jsonSchemaDefinition wraps the JSON schema
type jsonSchemaDefinition struct {
	Name   string     `json:"name"`
	Schema jsonSchema `json:"schema"`
}

// jsonSchema is the JSON schema for company profile extraction
type jsonSchema struct {
	Type       string                        `json:"type"`
	Properties map[string]jsonSchemaProperty `json:"properties"`
}

// jsonSchemaProperty defines a single JSON schema property
type jsonSchemaProperty struct {
	Type        string                        `json:"type"`
	Description string                        `json:"description"`
	Items       *jsonSchemaProperty           `json:"items,omitempty"`
	Properties  map[string]jsonSchemaProperty `json:"properties,omitempty"`
}

// browserRenderingResponse is the Cloudflare API response wrapper
type browserRenderingResponse struct {
	Success bool           `json:"success"`
	Result  CompanyProfile `json:"result"`
}

// RenderCompanyProfile extracts a structured company profile from the given domain
func (c *Client) RenderCompanyProfile(ctx context.Context, domain string) (CompanyProfile, error) {
	reqURL := c.apiURL(browserRenderingPath)
	body := browserRenderingRequest{
		URL:            fmt.Sprintf("https://%s", domain),
		ResponseFormat: buildCompanyProfileSchema(),
		GotoOptions:    &gotoOptions{WaitUntil: "networkidle2", Timeout: browserNavigationTimeout},
	}

	requester := httpsling.MustNew(
		httpsling.URL(reqURL),
		httpsling.Post(),
		httpsling.BearerAuth(c.apiToken),
		httpsling.JSONBody(body),
		httpsling.WithHTTPClient(c.httpClient),
	)

	var cfResp browserRenderingResponse

	resp, err := requester.ReceiveWithContext(ctx, &cfResp)
	if err != nil {
		return CompanyProfile{}, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is non-critical

	if resp.StatusCode != http.StatusOK {
		return CompanyProfile{}, fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	if !cfResp.Success {
		return CompanyProfile{}, ErrRenderingFailed
	}

	return cfResp.Result, nil
}

// buildCompanyProfileSchema constructs the JSON schema for company profile extraction
func buildCompanyProfileSchema() responseFormat {
	return responseFormat{
		Type: "json_schema",
		JSONSchema: jsonSchemaDefinition{
			Name: schemaName,
			Schema: jsonSchema{
				Type: "object",
				Properties: map[string]jsonSchemaProperty{
					"name": {
						Type:        "string",
						Description: "The company or organization name",
					},
					"description": {
						Type:        "string",
						Description: "A brief description of what the company does, in 1-2 sentences",
					},
					"industry": {
						Type:        "string",
						Description: "The primary industry the company operates in",
					},
					"products": {
						Type:        "array",
						Description: "Key products or services offered by the company",
						Items: &jsonSchemaProperty{
							Type:        "string",
							Description: "A product or service name",
						},
					},
					"location": {
						Type:        "string",
						Description: "The headquarters or primary location of the company",
					},
					"employee_range": {
						Type:        "string",
						Description: "The approximate employee count range, such as 1-10, 11-50, 51-200, 201-500, 501-1000, 1001-5000, 5000+",
					},
					"founded_year": {
						Type:        "string",
						Description: "The year the company was founded or established, if mentioned on the website (e.g., 2015, 2020). Leave empty if not found.",
					},
					"estimated_revenue": {
						Type:        "string",
						Description: "The estimated annual revenue range if mentioned or inferable from the website (e.g., $1M-$10M, $10M-$50M, $50M-$100M, $100M+). Leave empty if not discoverable.",
					},
					"social_links": {
						Type:        "object",
						Description: "URLs for the company's social media and community profiles found in the website header, footer, or about page",
						Properties: map[string]jsonSchemaProperty{
							"linkedin":  {Type: "string", Description: "LinkedIn company page URL"},
							"twitter":   {Type: "string", Description: "Twitter/X profile URL"},
							"github":    {Type: "string", Description: "GitHub organization URL"},
							"discord":   {Type: "string", Description: "Discord server invite URL"},
							"instagram": {Type: "string", Description: "Instagram profile URL"},
							"youtube":   {Type: "string", Description: "YouTube channel URL"},
							"facebook":  {Type: "string", Description: "Facebook page URL"},
						},
					},
					"technologies": {
						Type:        "array",
						Description: "Third-party SaaS tools, platforms, analytics services, and technology vendors detectable on the website (e.g., Google Analytics, Salesforce, HubSpot, Cloudflare, Intercom, Stripe, Segment, Zendesk). Only include vendor or product names, not web standards or protocols.",
						Items: &jsonSchemaProperty{
							Type:        "string",
							Description: "A technology vendor or SaaS platform name",
						},
					},
				},
			},
		},
	}
}
