# meok-go

**Official Go SDK for the MEOK Attestation API** — sign + verify HMAC-signed compliance attestations across the MEOK trade-compliance ecosystem.

> Part of the [MEOK AI Labs](https://meok.ai) ecosystem powering [haulage.app](https://haulage.app).

[![Go Reference](https://pkg.go.dev/badge/github.com/CSOAI-ORG/meok-go.svg)](https://pkg.go.dev/github.com/CSOAI-ORG/meok-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/CSOAI-ORG/meok-go)](https://goreportcard.com/report/github.com/CSOAI-ORG/meok-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)

## Install

```bash
go get github.com/CSOAI-ORG/meok-go
```

Go ≥ 1.22. Standard library only — no external dependencies.

## Quick start — verify a cert (no API key needed)

```go
package main

import (
    "context"
    "fmt"
    "log"

    meok "github.com/CSOAI-ORG/meok-go"
)

func main() {
    ctx := context.Background()
    cert := meok.Cert{
        CertID:              "...",
        SignatureSHA256HMAC: "...",
    }
    result, err := meok.VerifyPublic(ctx, cert, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("valid:", result.Valid, "—", result.Message)
}
```

## Sign a cert (requires an API key)

```go
c := meok.NewClient(
    meok.WithAPIKey(os.Getenv("MEOK_API_KEY")),
)

cert, err := c.Sign(ctx, meok.SignRequest{
    Regulation: "EU_AI_ACT_ANNEX_III",
    Entity:     "ACME Haulage Ltd",
    Score:      82,
    Findings: []string{
        "Tachograph data exported",
        "OCRS forecast GREEN",
    },
    ArticlesAudited: []string{"Art_9", "Art_10", "Art_15"},
})
if err != nil {
    log.Fatal(err)
}
fmt.Println("verify_url:", cert.VerifyURL)
```

## Error handling

All errors classify via `errors.Is`:

```go
_, err := c.Sign(ctx, req)
switch {
case errors.Is(err, meok.ErrAuth):
    // 401 — bad / missing API key
case errors.Is(err, meok.ErrValidation):
    // 400 — missing fields
case errors.Is(err, meok.ErrPayment):
    // 402 — Stripe session not paid
case errors.Is(err, meok.ErrNetwork):
    // connect / DNS / timeout
default:
    // other APIError — use errors.As(err, &apiErr) for status code
}
```

## Concurrency

`*Client` is safe for concurrent use. Reuse the same client across goroutines.

## Options

| Option              | What                                                        |
|---------------------|-------------------------------------------------------------|
| `WithAPIKey(key)`   | Set API key (overrides `MEOK_API_KEY` env).                 |
| `WithBaseURL(base)` | Override base URL (testing, edge).                          |
| `WithHTTPClient(h)` | Custom `*http.Client` — set your own timeout / transport.   |

## Environment variables

| Variable           | What                                                      | Default                                    |
|--------------------|-----------------------------------------------------------|--------------------------------------------|
| `MEOK_API_KEY`     | Default API key used when `WithAPIKey` is not passed.     | `""`                                       |
| `MEOK_API_BASE`    | Override base URL.                                        | `https://meok-attestation-api.vercel.app`  |

## Related

- [OpenAPI 3.1 spec](https://meok-attestation-api.vercel.app/openapi.json)
- [Interactive docs (Swagger UI)](https://meok-attestation-api.vercel.app/docs)
- [Python SDK](https://pypi.org/project/meok-sdk/)
- [TypeScript SDK](https://www.npmjs.com/package/@meok/sdk)
- [Haulage.app — 32-MCP catalogue](https://haulage.app)

## License

MIT — © 2026 MEOK AI Labs / CSOAI LTD.
