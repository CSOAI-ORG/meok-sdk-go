// Package meok is the official Go SDK for the MEOK Attestation API.
//
// It provides a small, idiomatic client for signing and verifying
// HMAC-SHA256 compliance attestations against the MEOK trade-compliance
// ecosystem.
//
// Quick start — verify a cert (no API key needed):
//
//	import "github.com/CSOAI-ORG/meok-go"
//
//	result, err := meok.VerifyPublic(ctx, cert, nil)
//	if err != nil { log.Fatal(err) }
//	fmt.Println(result.Valid, result.Message)
//
// Sign a cert (API key required):
//
//	c := meok.NewClient(meok.WithAPIKey(os.Getenv("MEOK_API_KEY")))
//	cert, err := c.Sign(ctx, meok.SignRequest{
//	    Regulation: "EU_AI_ACT_ANNEX_III",
//	    Entity:     "ACME Haulage Ltd",
//	    Score:      82,
//	    Findings:   []string{"Tachograph data exported", "OCRS GREEN"},
//	})
//
// All public APIs accept a context.Context and return typed errors.
package meok

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Version of this SDK. Updated by tag.
const Version = "0.1.0"

// DefaultBaseURL is the production MEOK Attestation API endpoint.
const DefaultBaseURL = "https://meok-attestation-api.vercel.app"

// UserAgent that the SDK sets on every outbound request.
const UserAgent = "meok-go/" + Version

// Assessment is the human-readable derivation from a score.
type Assessment string

const (
	Compliant    Assessment = "COMPLIANT"
	Partial      Assessment = "PARTIAL"
	NonCompliant Assessment = "NON_COMPLIANT"
)

// Tier is the resolved server-side tier of an API key.
type Tier string

const (
	Free       Tier = "free"
	Starter    Tier = "starter"
	Pro        Tier = "pro"
	Enterprise Tier = "enterprise"
)

// Cert is a signed attestation.
type Cert struct {
	CertID              string     `json:"cert_id,omitempty"`
	IssuedAt            string     `json:"issued_at,omitempty"`
	ExpiresAt           string     `json:"expires_at,omitempty"`
	Regulation          string     `json:"regulation,omitempty"`
	Entity              string     `json:"entity,omitempty"`
	Score               float64    `json:"score,omitempty"`
	Assessment          Assessment `json:"assessment,omitempty"`
	Findings            []string   `json:"findings,omitempty"`
	ArticlesAudited     []string   `json:"articles_audited,omitempty"`
	AuditorNotes        string     `json:"auditor_notes,omitempty"`
	Tier                Tier       `json:"tier,omitempty"`
	Issuer              string     `json:"issuer,omitempty"`
	Kid                 string     `json:"kid,omitempty"`
	VerifyURL           string     `json:"verify_url,omitempty"`
	SignatureSHA256HMAC string     `json:"signature_sha256_hmac,omitempty"`
}

// SignRequest is the input to (*Client).Sign.
type SignRequest struct {
	Regulation      string   `json:"regulation"`
	Entity          string   `json:"entity"`
	Score           float64  `json:"score"`
	Findings        []string `json:"findings,omitempty"`
	ArticlesAudited []string `json:"articles_audited,omitempty"`
	AuditorNotes    string   `json:"auditor_notes,omitempty"`
	Email           string   `json:"email,omitempty"`
}

// VerifyResult is the output of /verify.
type VerifyResult struct {
	Valid     bool   `json:"valid"`
	Message   string `json:"message"`
	CertID    string `json:"cert_id,omitempty"`
	VerifyURL string `json:"verify_url,omitempty"`
}

// HealthResult is the output of /health.
type HealthResult struct {
	OK      bool   `json:"ok"`
	Status  string `json:"status"`
	Service string `json:"service"`
	Kid     string `json:"kid"`
	Version string `json:"version"`
}

// Client is a Go client for the MEOK Attestation API. Safe for concurrent use.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key for authenticated calls.
func WithAPIKey(key string) Option { return func(c *Client) { c.apiKey = key } }

// WithBaseURL overrides the API base URL.
func WithBaseURL(base string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(base, "/") }
}

// WithHTTPClient swaps the underlying http.Client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// NewClient creates a Client. Reads MEOK_API_KEY + MEOK_API_BASE from the
// environment if those options are not supplied.
func NewClient(opts ...Option) *Client {
	c := &Client{
		apiKey:  os.Getenv("MEOK_API_KEY"),
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	if env := os.Getenv("MEOK_API_BASE"); env != "" {
		c.baseURL = strings.TrimRight(env, "/")
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ── Errors ──────────────────────────────────────────────────────────

// Error is the base for every error returned by the SDK.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string {
	if e.Op == "" {
		return e.Err.Error()
	}
	return e.Op + ": " + e.Err.Error()
}
func (e *Error) Unwrap() error { return e.Err }

// APIError is returned when the API responds with a non-2xx status.
type APIError struct {
	StatusCode int
	Message    string
	Body       []byte
}

func (e *APIError) Error() string {
	return fmt.Sprintf("[%d] %s", e.StatusCode, e.Message)
}

// Common APIError sentinels — use errors.Is / errors.As.
var (
	ErrAuth       = errors.New("meok: 401 unauthorized")
	ErrValidation = errors.New("meok: 400 validation")
	ErrPayment    = errors.New("meok: 402 payment required")
	ErrNetwork    = errors.New("meok: network failure")
)

// classify wraps an APIError with the appropriate sentinel.
func classify(status int, body []byte) error {
	var b struct{ Error, Message string }
	_ = json.Unmarshal(body, &b)
	msg := b.Error
	if msg == "" {
		msg = b.Message
	}
	if msg == "" {
		msg = "(no error message in response body)"
	}
	apiErr := &APIError{StatusCode: status, Message: msg, Body: body}
	switch status {
	case 401:
		return fmt.Errorf("%w: %w", ErrAuth, apiErr)
	case 400:
		return fmt.Errorf("%w: %w", ErrValidation, apiErr)
	case 402:
		return fmt.Errorf("%w: %w", ErrPayment, apiErr)
	}
	return apiErr
}

// ── Public surface ──────────────────────────────────────────────────

// Health returns liveness info for the API.
func (c *Client) Health(ctx context.Context) (*HealthResult, error) {
	var out HealthResult
	if err := c.do(ctx, "GET", "/health", nil, &out, false, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// Sign issues a new signed attestation. Requires an API key.
func (c *Client) Sign(ctx context.Context, req SignRequest) (*Cert, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("%w: client.Sign requires an API key", ErrAuth)
	}
	body := map[string]any{
		"api_key":          c.apiKey,
		"regulation":       req.Regulation,
		"entity":           req.Entity,
		"score":            req.Score,
		"findings":         req.Findings,
		"articles_audited": req.ArticlesAudited,
	}
	if req.AuditorNotes != "" {
		body["auditor_notes"] = req.AuditorNotes
	}
	if req.Email != "" {
		body["email"] = req.Email
	}
	var out Cert
	if err := c.do(ctx, "POST", "/sign", body, &out, true, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify checks a cert against the API. No API key required.
func (c *Client) Verify(ctx context.Context, cert Cert) (*VerifyResult, error) {
	var out VerifyResult
	if err := c.do(ctx, "POST", "/verify", cert, &out, false, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyPublic is a one-shot public verification. baseURL=nil → DefaultBaseURL.
func VerifyPublic(ctx context.Context, cert Cert, opts *PublicOptions) (*VerifyResult, error) {
	c := NewClient()
	if opts != nil {
		if opts.BaseURL != "" {
			c.baseURL = strings.TrimRight(opts.BaseURL, "/")
		}
		if opts.HTTPClient != nil {
			c.httpClient = opts.HTTPClient
		}
	}
	return c.Verify(ctx, cert)
}

// PublicOptions customise the VerifyPublic helper.
type PublicOptions struct {
	BaseURL    string
	HTTPClient *http.Client
}

// ── Internal ────────────────────────────────────────────────────────

func (c *Client) do(
	ctx context.Context,
	method, path string,
	body any,
	out any,
	useAuth bool,
	extraHeaders map[string]string,
) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return &Error{Op: "encode body", Err: err}
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return &Error{Op: "build request", Err: err}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if useAuth && c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNetwork, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: read body: %s", ErrNetwork, err)
	}
	if resp.StatusCode >= 400 {
		return classify(resp.StatusCode, respBody)
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return &Error{Op: "decode response", Err: err}
		}
	}
	return nil
}
