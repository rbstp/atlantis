// Copyright 2025 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

func setupTestOIDCProvider(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "http://test-issuer",
			"authorization_endpoint": "http://test-issuer/authorize",
			"token_endpoint":         "http://test-issuer/token",
			"userinfo_endpoint":      "http://test-issuer/userinfo",
			"jwks_uri":               "http://test-issuer/keys",
		})
	})

	return httptest.NewServer(mux)
}

func TestNewOIDCHandler(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)

	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}, logger)
	Ok(t, err)
	Assert(t, handler != nil, "handler should not be nil")
}

func TestNewOIDCHandler_InvalidIssuer(t *testing.T) {
	logger := logging.NewNoopLogger(t)

	_, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    "http://localhost:1", // invalid port
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Assert(t, err != nil, "expected error for invalid issuer")
}

func TestOIDCHandler_HandleLogin(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)
	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Ok(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	w := httptest.NewRecorder()

	handler.HandleLogin(w, req)

	Equals(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	Assert(t, location != "", "expected redirect Location header")
}

func TestOIDCHandler_HandleCallback_MissingState(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)
	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Ok(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	w := httptest.NewRecorder()

	handler.HandleCallback(w, req)

	Equals(t, http.StatusBadRequest, w.Code)
}

func TestOIDCHandler_HandleCallback_InvalidState(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)
	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Ok(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=invalid-state", nil)
	w := httptest.NewRecorder()

	handler.HandleCallback(w, req)

	Equals(t, http.StatusBadRequest, w.Code)
}

func TestOIDCHandler_IsAuthenticated_NoCookie(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)
	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Ok(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Assert(t, !handler.IsAuthenticated(req), "should not be authenticated without cookie")
}

func TestOIDCHandler_IsAuthenticated_InvalidCookie(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)
	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Ok(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "atlantis_oidc",
		Value: "invalid-session-id",
	})
	Assert(t, !handler.IsAuthenticated(req), "should not be authenticated with invalid session")
}

func TestOIDCSession_Expiry(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)
	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Ok(t, err)

	handler.SetSession("expired-session", &OIDCSession{
		Email:     "test@example.com",
		Name:      "Test User",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "atlantis_oidc",
		Value: "expired-session",
	})
	Assert(t, !handler.IsAuthenticated(req), "expired session should not be authenticated")
}

func TestOIDCSession_Valid(t *testing.T) {
	provider := setupTestOIDCProvider(t)
	defer provider.Close()

	logger := logging.NewNoopLogger(t)
	handler, err := NewOIDCHandler(t.Context(), OIDCConfig{
		Enabled:      true,
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    provider.URL,
		RedirectURL:  "http://localhost:4141/auth/oidc/callback",
	}, logger)
	Ok(t, err)

	handler.SetSession("valid-session", &OIDCSession{
		Email:     "test@example.com",
		Name:      "Test User",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "atlantis_oidc",
		Value: "valid-session",
	})
	Assert(t, handler.IsAuthenticated(req), "valid session should be authenticated")
}
