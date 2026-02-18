package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/theopenlane/sleuth/internal/cloudflare"
	"github.com/theopenlane/sleuth/internal/slack"
)

// slackMessageTruncateLimit is the maximum length for text fields in Slack messages
const slackMessageTruncateLimit = 2000

// EnrichRequest represents a domain enrichment request.
type EnrichRequest struct {
	// Domain is the domain to enrich.
	Domain string `json:"domain,omitempty"`
	// Email is the email address to extract domain from and enrich.
	Email string `json:"email,omitempty"`
	// NotifySlack controls whether to send a Slack notification. Defaults to true when omitted.
	NotifySlack *bool `json:"notify_slack,omitempty"`
}

// EnrichResponse represents the enrichment response.
type EnrichResponse struct {
	// Success indicates whether the enrichment completed successfully.
	Success bool `json:"success"`
	// Data holds the enrichment result when successful.
	Data *EnrichResult `json:"data,omitempty"`
	// Error is the normalized error payload when enrichment fails.
	Error *Error `json:"error,omitempty"`
}

// EnrichResult holds the domain enrichment data.
type EnrichResult struct {
	// Domain is the domain that was enriched.
	Domain string `json:"domain"`
	// Email is the email that triggered the enrichment, if provided.
	Email string `json:"email,omitempty"`
	// Profile is the extracted company profile.
	Profile cloudflare.CompanyProfile `json:"profile"`
	// SlackNotified indicates whether a Slack notification was sent.
	SlackNotified bool `json:"slack_notified"`
}

// handleEnrich processes domain enrichment requests.
func (h *Handler) handleEnrich(w http.ResponseWriter, r *http.Request) {
	if h.enricher == nil {
		respondEnrichError(w, http.StatusServiceUnavailable, errCodeUnavailable, ErrEnricherNotConfigured.Error())
		return
	}

	if h.maxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)
	}

	var req EnrichRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondEnrichError(w, http.StatusBadRequest, errCodeInvalidRequest, ErrInvalidRequestBody.Error())
		return
	}

	domain := req.Domain

	if domain == "" && req.Email != "" {
		extracted, err := extractEmailDomain(req.Email)
		if err != nil {
			respondEnrichError(w, http.StatusBadRequest, errCodeValidation, err.Error())
			return
		}

		domain = extracted
	}

	if domain == "" {
		respondEnrichError(w, http.StatusBadRequest, errCodeValidation, ErrDomainRequired.Error())
		return
	}

	profile, err := h.enricher.RenderCompanyProfile(r.Context(), domain)
	if err != nil {
		log.Error().Err(err).Str("domain", domain).Msg("domain enrichment failed")
		respondEnrichError(w, http.StatusBadGateway, errCodeInternal, fmt.Sprintf("enrichment failed: %v", err))
		return
	}

	result := &EnrichResult{
		Domain:  domain,
		Email:   req.Email,
		Profile: profile,
	}

	shouldNotify := req.NotifySlack == nil || *req.NotifySlack
	if shouldNotify && h.notifier != nil {
		msg := buildEnrichmentSlackMessage(domain, req.Email, profile)

		if err := h.notifier.Send(r.Context(), msg); err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("slack notification failed")
		} else {
			result.SlackNotified = true
		}
	}

	writeJSON(w, http.StatusOK, EnrichResponse{
		Success: true,
		Data:    result,
	})
}

// buildEnrichmentSlackMessage formats a company profile into a Slack Block Kit message
func buildEnrichmentSlackMessage(domain, email string, profile cloudflare.CompanyProfile) slack.Message {
	headerText := fmt.Sprintf("Domain Enrichment: %s", domain)

	blocks := []slack.Block{
		{
			Type: "header",
			Text: &slack.TextObject{Type: "plain_text", Text: headerText},
		},
	}

	if profile.Name != "" || profile.Description != "" {
		summaryParts := []string{}
		if profile.Name != "" {
			summaryParts = append(summaryParts, fmt.Sprintf("*%s*", profile.Name))
		}

		if profile.Description != "" {
			summaryParts = append(summaryParts, profile.Description)
		}

		blocks = append(blocks, slack.Block{
			Type: "section",
			Text: &slack.TextObject{
				Type: "mrkdwn",
				Text: truncateText(strings.Join(summaryParts, "\n"), slackMessageTruncateLimit),
			},
		})
	}

	var fields []slack.TextObject

	if profile.Industry != "" {
		fields = append(fields, slack.TextObject{Type: "mrkdwn", Text: fmt.Sprintf("*Industry:*\n%s", profile.Industry)})
	}

	if profile.Location != "" {
		fields = append(fields, slack.TextObject{Type: "mrkdwn", Text: fmt.Sprintf("*Location:*\n%s", profile.Location)})
	}

	if profile.EmployeeRange != "" {
		fields = append(fields, slack.TextObject{Type: "mrkdwn", Text: fmt.Sprintf("*Employees:*\n%s", profile.EmployeeRange)})
	}

	if email != "" {
		fields = append(fields, slack.TextObject{Type: "mrkdwn", Text: fmt.Sprintf("*Signup Email:*\n%s", email)})
	}

	if len(fields) > 0 {
		blocks = append(blocks, slack.Block{
			Type:   "section",
			Fields: fields,
		})
	}

	if len(profile.Products) > 0 {
		productText := fmt.Sprintf("*Products/Services:*\n%s", strings.Join(profile.Products, ", "))
		blocks = append(blocks, slack.Block{
			Type: "section",
			Text: &slack.TextObject{
				Type: "mrkdwn",
				Text: truncateText(productText, slackMessageTruncateLimit),
			},
		})
	}

	fallback := fmt.Sprintf("Domain Enrichment: %s", domain)
	if profile.Name != "" {
		fallback = fmt.Sprintf("Domain Enrichment: %s (%s)", domain, profile.Name)
	}

	return slack.Message{
		Text:   fallback,
		Blocks: blocks,
	}
}

// truncateText truncates text to the specified maximum length, adding an ellipsis if truncated
func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}

	return text[:maxLen-3] + "..."
}

func respondEnrichError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, EnrichResponse{
		Success: false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	})
}
