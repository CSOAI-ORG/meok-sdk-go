// Package csoai provides a Go client for the CSOAI.org compliance platform.
//
// Quick start:
//
//	import "github.com/CSOAI-ORG/meok-go/csoai"
//
//	client := csoai.NewClient()
//	mapData, err := client.GetComplianceMap(ctx)
//
package csoai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	Version          = "0.1.0"
	DefaultBaseURL   = "https://csoai.org"
	UserAgent        = "meok-go-csoai/" + Version
)

// ── Client ──────────────────────────────────────────────────────────

type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
}

type Option func(*Client)

func WithBaseURL(base string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(base, "/") }
}

func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	if env := os.Getenv("CSOAI_BASE_URL"); env != "" {
		c.baseURL = strings.TrimRight(env, "/")
	}
	if env := os.Getenv("CSOAI_API_KEY"); env != "" {
		c.apiKey = env
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ── Errors ──────────────────────────────────────────────────────────

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

// ── Models ──────────────────────────────────────────────────────────

type Region struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	StatusLabel      string   `json:"status_label"`
	Color            string   `json:"color"`
	DaysToDeadline   int      `json:"days_to_deadline"`
	DeadlineDate     *string  `json:"deadline_date"`
	Frameworks       []string `json:"frameworks"`
	Agents           int      `json:"agents"`
	ComplianceScore  int      `json:"compliance_score"`
	OpenViolations   int      `json:"open_violations"`
}

type ComplianceMap struct {
	Version          string   `json:"version"`
	GeneratedAt      string   `json:"generated_at"`
	TotalRegions     int      `json:"total_regions"`
	TotalFrameworks  int      `json:"total_frameworks"`
	Regions          []Region `json:"regions"`
	GlobalStats      struct {
		ActiveSystems    int `json:"active_systems"`
		PDCACycles       int `json:"pdca_cycles"`
		MCPServers       int `json:"mcp_servers"`
		OpenViolations   int `json:"open_violations"`
		AvgCompliance    int `json:"avg_compliance"`
		PendingApprovals int `json:"pending_approvals"`
	} `json:"global_stats"`
}

type CrosswalkRow struct {
	Domain    string `json:"domain"`
	EUAiAct   string `json:"eu_ai_act"`
	NIST      string `json:"nist_ai_rmf"`
	ISO       string `json:"iso_42001"`
	TC260     string `json:"tc260"`
	Risk      string `json:"risk"`
}

type Crosswalk struct {
	Version          string         `json:"version"`
	GeneratedAt      string         `json:"generated_at"`
	TotalFrameworks  int            `json:"total_frameworks"`
	TotalDomains     int            `json:"total_domains"`
	Frameworks       []Framework    `json:"frameworks"`
	Crosswalk        []CrosswalkRow `json:"crosswalk"`
}

type Framework struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Region        string  `json:"region"`
	Status        string  `json:"status"`
	EffectiveDate *string `json:"effective_date"`
}

type DOMEStatus struct {
	Version          string `json:"version"`
	GeneratedAt      string `json:"generated_at"`
	Status           string `json:"status"`
	Layer            string `json:"layer"`
	Stats            struct {
		ActiveSystems    int `json:"active_systems"`
		PDCACycles       int `json:"pdca_cycles"`
		MCPServers       int `json:"mcp_servers"`
		OpenViolations   int `json:"open_violations"`
		AvgCompliance    int `json:"avg_compliance"`
		PendingApprovals int `json:"pending_approvals"`
	} `json:"stats"`
	RegionHeat       []struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Status string `json:"status"`
		Color  string `json:"color"`
	} `json:"region_heat"`
	RegulatoryClocks []struct {
		Name          string `json:"name"`
		DaysRemaining int    `json:"days_remaining"`
		Deadline      string `json:"deadline"`
		Color         string `json:"color"`
	} `json:"regulatory_clocks"`
}

type CouncilVotes struct {
	Version      string `json:"version"`
	GeneratedAt  string `json:"generated_at"`
	Council      struct {
		Name               string `json:"name"`
		TotalNodes         int    `json:"total_nodes"`
		OnlineNodes        int    `json:"online_nodes"`
		DegradedNodes      int    `json:"degraded_nodes"`
		FaultTolerance     int    `json:"fault_tolerance"`
		ConsensusThreshold int    `json:"consensus_threshold"`
	} `json:"council"`
	Nodes        []struct {
		Region     string `json:"region"`
		Agents     int    `json:"agents"`
		Consensus  int    `json:"consensus"`
		Status     string `json:"status"`
		LastSeen   string `json:"last_seen"`
	} `json:"nodes"`
	RecentVotes  []struct {
		Topic       string `json:"topic"`
		Result      string `json:"result"`
		Count       string `json:"count"`
		Time        string `json:"time"`
		ProposalID  string `json:"proposal_id"`
	} `json:"recent_votes"`
}

type SigilVerification struct {
	Valid            bool   `json:"valid"`
	CertID           string `json:"cert_id"`
	SystemName       string `json:"system_name"`
	Framework        string `json:"framework"`
	ComplianceScore  float64 `json:"compliance_score"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
	Issuer           string `json:"issuer"`
	Status           string `json:"status"`
}

// ── API Methods ─────────────────────────────────────────────────────

func (c *Client) GetComplianceMap(ctx context.Context) (*ComplianceMap, error) {
	var out ComplianceMap
	if err := c.get(ctx, "/api/map.json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetRegion(ctx context.Context, regionID string) (*Region, error) {
	m, err := c.GetComplianceMap(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range m.Regions {
		if r.ID == regionID {
			return &r, nil
		}
	}
	return nil, &Error{Op: "get_region", Err: fmt.Errorf("region %q not found", regionID)}
}

func (c *Client) GetCrosswalk(ctx context.Context) (*Crosswalk, error) {
	var out Crosswalk
	if err := c.get(ctx, "/api/crosswalk.json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetDOMEStatus(ctx context.Context) (*DOMEStatus, error) {
	var out DOMEStatus
	if err := c.get(ctx, "/api/dome/status.json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetCouncilVotes(ctx context.Context) (*CouncilVotes, error) {
	var out CouncilVotes
	if err := c.get(ctx, "/api/council/votes.json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) VerifySigil(ctx context.Context, certID string) (*SigilVerification, error) {
	var out SigilVerification
	if err := c.get(ctx, fmt.Sprintf("/api/sigil/verify.json?id=%s", certID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetRegulatoryCountdowns(ctx context.Context) ([]struct {
	Name          string `json:"name"`
	DaysRemaining int    `json:"days_remaining"`
	Deadline      string `json:"deadline"`
	Color         string `json:"color"`
}, error) {
	dome, err := c.GetDOMEStatus(ctx)
	if err != nil {
		return nil, err
	}
	return dome.RegulatoryClocks, nil
}

// ── Internal ────────────────────────────────────────────────────────

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return &Error{Op: "build request", Err: err}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-CSOAI-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &Error{Op: "http request", Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Error{Op: "read body", Err: err}
	}
	if resp.StatusCode >= 400 {
		return &Error{Op: "api response", Err: fmt.Errorf("[%d] %s", resp.StatusCode, string(body))}
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return &Error{Op: "decode json", Err: err}
		}
	}
	return nil
}
