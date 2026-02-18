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
	// WebsiteTitle is the page title from the website
	WebsiteTitle string `json:"website_title"`
}

// browserRenderingRequest is the request body for the browser rendering API
type browserRenderingRequest struct {
	URL            string         `json:"url"`
	ResponseFormat responseFormat `json:"response_format"`
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
	Type        string              `json:"type"`
	Description string              `json:"description"`
	Items       *jsonSchemaProperty `json:"items,omitempty"`
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
					"website_title": {
						Type:        "string",
						Description: "The title of the website homepage",
					},
				},
			},
		},
	}
}
