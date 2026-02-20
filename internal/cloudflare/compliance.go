package cloudflare

import (
	"context"
	"fmt"
	"net/http"

	"github.com/theopenlane/httpsling"
)

const (
	// compliancePageSchemaName is the identifier for the compliance page analysis JSON schema
	compliancePageSchemaName = "compliance_page"
)

// CompliancePage holds structured compliance information extracted from a single page
type CompliancePage struct {
	// URL is the page URL that was analyzed
	URL string `json:"url"`
	// PageType categorizes the compliance document (e.g., privacy_policy, terms_of_service, trust_center, dpa, soc2_report, security, subprocessors, gdpr, cookie_policy)
	PageType string `json:"page_type"`
	// Title is the page title
	Title string `json:"title"`
	// Summary is a brief description of the page content
	Summary string `json:"summary"`
	// Frameworks lists compliance frameworks or certifications mentioned (e.g., SOC 2, ISO 27001, GDPR, HIPAA)
	Frameworks []string `json:"frameworks"`
	// LastUpdated is the last updated or effective date mentioned on the page
	LastUpdated string `json:"last_updated"`
	// DownloadLinks contains URLs for downloadable reports or documents found on the page
	DownloadLinks []string `json:"download_links"`
	// Subprocessors lists third-party vendors or sub-processors mentioned on the page
	Subprocessors []string `json:"subprocessors,omitempty"`
	// ComplianceLinks lists URLs to compliance documents (privacy policy, terms, DPA, etc.) found on the page
	ComplianceLinks []string `json:"compliance_links,omitempty"`
}

// compliancePageResponse is the Cloudflare API response for page analysis
type compliancePageResponse struct {
	Success bool           `json:"success"`
	Result  CompliancePage `json:"result"`
}

// AnalyzeCompliancePage renders a specific URL and extracts structured compliance information
func (c *Client) AnalyzeCompliancePage(ctx context.Context, pageURL string) (CompliancePage, error) {
	reqURL := c.apiURL(browserRenderingPath)
	body := browserRenderingRequest{
		URL:            pageURL,
		ResponseFormat: buildCompliancePageSchema(),
		GotoOptions:    &gotoOptions{WaitUntil: "networkidle2", Timeout: browserNavigationTimeout},
	}

	requester := httpsling.MustNew(
		httpsling.URL(reqURL),
		httpsling.Post(),
		httpsling.BearerAuth(c.apiToken),
		httpsling.JSONBody(body),
		httpsling.WithHTTPClient(c.httpClient),
	)

	var cfResp compliancePageResponse

	resp, err := requester.ReceiveWithContext(ctx, &cfResp)
	if err != nil {
		return CompliancePage{}, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is non-critical

	if resp.StatusCode != http.StatusOK {
		return CompliancePage{}, fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	if !cfResp.Success {
		return CompliancePage{}, ErrRenderingFailed
	}

	result := cfResp.Result
	result.URL = pageURL

	return result, nil
}

// buildCompliancePageSchema constructs the JSON schema for analyzing a compliance page.
// The schema instructs Cloudflare's browser rendering AI to extract compliance
// frameworks, subprocessor/vendor names, downloadable documents, and links to
// other compliance pages found on trust center and security pages.
func buildCompliancePageSchema() responseFormat {
	return responseFormat{
		Type: "json_schema",
		JSONSchema: jsonSchemaDefinition{
			Name: compliancePageSchemaName,
			Schema: jsonSchema{
				Type: "object",
				Properties: map[string]jsonSchemaProperty{
					"page_type": {
						Type:        "string",
						Description: "The type of compliance document: privacy_policy, terms_of_service, trust_center, dpa, soc2_report, security, subprocessors, gdpr, cookie_policy, or other",
					},
					"title": {
						Type:        "string",
						Description: "The page title or main heading",
					},
					"summary": {
						Type:        "string",
						Description: "A brief 1-2 sentence summary of what this page covers",
					},
					"frameworks": {
						Type:        "array",
						Description: "Compliance frameworks, certifications, or standards that this company has ACHIEVED or is CERTIFIED for, as stated on this page. Only include frameworks they claim to have completed — not ones they are pursuing or planning. Examples: SOC 2 Type II, ISO 27001, GDPR, HIPAA, PCI DSS, CCPA, FedRAMP.",
						Items: &jsonSchemaProperty{
							Type:        "string",
							Description: "A compliance framework or certification name",
						},
					},
					"last_updated": {
						Type:        "string",
						Description: "The last updated, effective date, or revision date mentioned on the page, if any. Format as found on the page.",
					},
					"download_links": {
						Type:        "array",
						Description: "URLs for downloadable documents, reports, or certificates found on this page (PDF links, report downloads, certificate images)",
						Items: &jsonSchemaProperty{
							Type:        "string",
							Description: "A download URL",
						},
					},
					"subprocessors": {
						Type:        "array",
						Description: "Names of third-party vendors, sub-processors, data processors, or service providers listed on this page. Extract the company or product name for each (e.g., AWS, Google Cloud, Stripe, Cloudflare, Datadog). Only include names explicitly listed as sub-processors or third-party vendors.",
						Items: &jsonSchemaProperty{
							Type:        "string",
							Description: "A vendor or sub-processor company name",
						},
					},
					"compliance_links": {
						Type:        "array",
						Description: "URLs linking to compliance-related documents found on this page: privacy policies, terms of service, data processing agreements, SOC 2 reports, security whitepapers, subprocessor lists, or other compliance documents. Include both internal and external links.",
						Items: &jsonSchemaProperty{
							Type:        "string",
							Description: "A URL to a compliance document",
						},
					},
				},
			},
		},
	}
}
