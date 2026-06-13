// Package main demonstrates basic usage of the MEOK Go SDK.
//
// Run:
//
//	MEOK_API_KEY=sk_meok_xxxxxxxx go run examples/csoai_basic.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/CSOAI-ORG/meok-go"
)

func main() {
	ctx := context.Background()
	apiKey := os.Getenv("MEOK_API_KEY")
	if apiKey == "" {
		apiKey = "sk_meok_demo_xxxxxxxx"
	}

	// ── 1. Sign a compliance attestation ───────────────────────────
	c := meok.NewClient(meok.WithAPIKey(apiKey))

	cert, err := c.Sign(ctx, meok.SignRequest{
		Regulation: "EU_AI_ACT_ANNEX_III",
		Entity:     "ACME Haulage Ltd",
		Score:      82,
		Findings: []string{
			"Tachograph data exported successfully",
			"OCRS forecast: GREEN",
			"Driver CPC records up to date",
		},
	})
	if err != nil {
		log.Fatalf("sign failed: %v", err)
	}

	fmt.Println("✅ Attestation signed")
	fmt.Printf("   Cert ID : %s\n", cert.CertID)
	fmt.Printf("   Score   : %.0f\n", cert.Score)
	fmt.Printf("   Tier    : %s\n", cert.Tier)
	fmt.Printf("   Verify  : %s\n", cert.VerifyURL)

	// ── 2. Public verification (no API key needed) ───────────────────
	result, err := meok.VerifyPublic(ctx, *cert, nil)
	if err != nil {
		log.Fatalf("verify failed: %v", err)
	}
	fmt.Printf("\n🔍 Verification result: %v — %s\n", result.Valid, result.Message)

	// ── 3. Health check ────────────────────────────────────────────
	health, err := c.Health(ctx)
	if err != nil {
		log.Fatalf("health check failed: %v", err)
	}
	fmt.Printf("\n🏥 API health: %s (v%s)\n", health.Status, health.Version)

	// ── 4. Batch sign with timeout ─────────────────────────────────
	entities := []struct {
		Name string
		Score float64
		Reg  string
	}{
		{"Fleet A", 88, "EU_AI_ACT_ANNEX_III"},
		{"Fleet B", 74, "EU_AI_ACT_ANNEX_IV"},
		{"Fleet C", 95, "NIST_AI_RMF"},
	}

	fmt.Println("\n📦 Batch results:")
	for _, e := range entities {
		ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
		c2, err := c.Sign(ctx2, meok.SignRequest{
			Regulation: e.Reg,
			Entity:     e.Name,
			Score:      e.Score,
			Findings:   []string{fmt.Sprintf("Automated assessment for %s", e.Name)},
		})
		cancel()
		if err != nil {
			fmt.Printf("   • %s: ERROR %v\n", e.Name, err)
			continue
		}
		fmt.Printf("   • %s: %.0f → %s\n", c2.Entity, c2.Score, c2.Assessment)
	}
}
