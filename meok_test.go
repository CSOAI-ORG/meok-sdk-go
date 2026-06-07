package meok

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, routes map[string]func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, handler := range routes {
		mux.HandleFunc(path, handler)
	}
	return httptest.NewServer(mux)
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/health": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(HealthResult{OK: true, Status: "ok", Service: "meok"})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	result, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !result.OK {
		t.Fatal("expected OK=true")
	}
}

func TestSignWithoutKey(t *testing.T) {
	c := NewClient(WithBaseURL("http://localhost:1"))
	c.apiKey = ""
	_, err := c.Sign(context.Background(), SignRequest{Regulation: "GDPR", Entity: "X", Score: 50})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got: %v", err)
	}
}

func TestSignSuccess(t *testing.T) {
	srv := newTestServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/sign": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-API-Key") != "sk_test" {
				t.Errorf("expected X-API-Key sk_test, got %q", r.Header.Get("X-API-Key"))
			}
			body, _ := readJSON(r)
			if body["regulation"] != "GDPR" {
				t.Errorf("expected regulation=GDPR, got %v", body["regulation"])
			}
			_ = json.NewEncoder(w).Encode(Cert{
				CertID:     "abc123",
				Regulation: "GDPR",
				Score:      80,
				Assessment: Compliant,
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL), WithAPIKey("sk_test"))
	cert, err := c.Sign(context.Background(), SignRequest{
		Regulation: "GDPR",
		Entity:     "ACME",
		Score:      80,
		Findings:   []string{"X"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if cert.CertID != "abc123" {
		t.Fatalf("expected cert_id abc123, got %s", cert.CertID)
	}
}

func TestSign400Validation(t *testing.T) {
	srv := newTestServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/sign": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"regulation required"}`))
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL), WithAPIKey("sk_test"))
	_, err := c.Sign(context.Background(), SignRequest{Regulation: "", Entity: "X", Score: 50})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestVerify(t *testing.T) {
	srv := newTestServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/verify": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(VerifyResult{
				Valid:   true,
				Message: "ok",
				CertID:  "abc123",
			})
		},
	})
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	result, err := c.Verify(context.Background(), Cert{CertID: "abc123"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid=true")
	}
}

func TestVerifyPublic(t *testing.T) {
	srv := newTestServer(t, map[string]func(http.ResponseWriter, *http.Request){
		"/verify": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(VerifyResult{Valid: false, Message: "expired"})
		},
	})
	defer srv.Close()

	result, err := VerifyPublic(context.Background(), Cert{CertID: "stale"}, &PublicOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("VerifyPublic: %v", err)
	}
	if result.Valid {
		t.Fatal("expected valid=false")
	}
}

func TestNetworkError(t *testing.T) {
	c := NewClient(WithBaseURL("http://127.0.0.1:1"))
	_, err := c.Health(context.Background())
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected ErrNetwork, got: %v", err)
	}
}

// helper
func readJSON(r *http.Request) (map[string]any, error) {
	var out map[string]any
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// silence unused import warnings if helpers shift
var _ = strings.TrimSpace
