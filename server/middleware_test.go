// Copyright 2025 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
	"github.com/urfave/negroni/v3"

	. "github.com/runatlantis/atlantis/testing"
)

func TestRequestLogger_BasicAuth_Allowed(t *testing.T) {
	logger := logging.NewNoopLogger(t)
	rl := &RequestLogger{
		logger:            logger,
		WebAuthentication: true,
		WebUsername:        "admin",
		WebPassword:        "secret",
	}

	called := false
	next := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "secret")
	w := negroni.NewResponseWriter(httptest.NewRecorder())

	rl.ServeHTTP(w, req, next)
	Assert(t, called, "next handler should have been called")
}

func TestRequestLogger_BasicAuth_Denied(t *testing.T) {
	logger := logging.NewNoopLogger(t)
	rl := &RequestLogger{
		logger:            logger,
		WebAuthentication: true,
		WebUsername:        "admin",
		WebPassword:        "secret",
	}

	called := false
	next := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	w := negroni.NewResponseWriter(httptest.NewRecorder())

	rl.ServeHTTP(w, req, next)
	Assert(t, !called, "next handler should not have been called")
	Equals(t, http.StatusUnauthorized, w.Status())
}

func TestRequestLogger_NoAuth_AllowedPaths(t *testing.T) {
	logger := logging.NewNoopLogger(t)
	rl := &RequestLogger{
		logger:            logger,
		WebAuthentication: true,
		WebUsername:        "admin",
		WebPassword:        "secret",
	}

	allowedPaths := []string{"/events", "/healthz", "/status", "/api/plan", "/auth/oidc/login", "/auth/oidc/callback"}

	for _, path := range allowedPaths {
		t.Run(path, func(t *testing.T) {
			called := false
			next := func(w http.ResponseWriter, r *http.Request) {
				called = true
			}

			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := negroni.NewResponseWriter(httptest.NewRecorder())

			rl.ServeHTTP(w, req, next)
			Assert(t, called, "next handler should have been called for path %s", path)
		})
	}
}

func TestRequestLogger_OIDC_Redirect(t *testing.T) {
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

	rl := &RequestLogger{
		logger:            logger,
		WebAuthentication: true,
		OIDCHandler:       handler,
	}

	called := false
	next := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := negroni.NewResponseWriter(httptest.NewRecorder())

	rl.ServeHTTP(w, req, next)
	Assert(t, !called, "next handler should not have been called without OIDC session")
	Equals(t, http.StatusFound, w.Status())
}

func TestRequestLogger_OIDC_Authenticated(t *testing.T) {
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

	rl := &RequestLogger{
		logger:            logger,
		WebAuthentication: true,
		OIDCHandler:       handler,
	}

	called := false
	next := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "atlantis_oidc",
		Value: "valid-session",
	})
	w := negroni.NewResponseWriter(httptest.NewRecorder())

	rl.ServeHTTP(w, req, next)
	Assert(t, called, "next handler should have been called with valid OIDC session")
}

func TestRequestLogger_AuthDisabled(t *testing.T) {
	logger := logging.NewNoopLogger(t)
	rl := &RequestLogger{
		logger:            logger,
		WebAuthentication: false,
	}

	called := false
	next := func(w http.ResponseWriter, r *http.Request) {
		called = true
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := negroni.NewResponseWriter(httptest.NewRecorder())

	rl.ServeHTTP(w, req, next)
	Assert(t, called, "next handler should be called when auth is disabled")
}
