// Copyright 2025 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
	"golang.org/x/oauth2"
)

// OIDCConfig holds configuration for OIDC authentication.
type OIDCConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	IssuerURL    string
	RedirectURL  string
	Scopes       []string
	CookieName   string
	CookieSecret []byte
}

// OIDCHandler manages the OIDC authentication flow.
type OIDCHandler struct {
	config      OIDCConfig
	oauth2Cfg   *oauth2.Config
	logger      logging.SimpleLogging
	sessions    map[string]*OIDCSession
	states      map[string]time.Time
	mu          sync.RWMutex
	providerCfg *oidcProviderConfig
}

// oidcProviderConfig holds the provider endpoints discovered from the issuer.
type oidcProviderConfig struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

// OIDCSession represents an authenticated OIDC session.
type OIDCSession struct {
	Email     string
	Name      string
	ExpiresAt time.Time
}

// NewOIDCHandler creates a new OIDC handler by discovering the provider configuration.
func NewOIDCHandler(ctx context.Context, config OIDCConfig, logger logging.SimpleLogging) (*OIDCHandler, error) {
	// Discover the OIDC provider configuration
	providerCfg, err := discoverOIDCProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discovering OIDC provider: %w", err)
	}

	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  providerCfg.AuthorizationEndpoint,
			TokenURL: providerCfg.TokenEndpoint,
		},
	}

	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = "atlantis_oidc"
	}

	return &OIDCHandler{
		config:      config,
		oauth2Cfg:   oauth2Cfg,
		logger:      logger,
		sessions:    make(map[string]*OIDCSession),
		states:      make(map[string]time.Time),
		providerCfg: providerCfg,
	}, nil
}

// discoverOIDCProvider fetches the OpenID Connect discovery document.
func discoverOIDCProvider(ctx context.Context, issuerURL string) (*oidcProviderConfig, error) {
	wellKnownURL := issuerURL + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching discovery document from %s: %w", wellKnownURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var cfg oidcProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding discovery document: %w", err)
	}

	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document missing required endpoints")
	}

	return &cfg, nil
}

// HandleLogin initiates the OIDC authentication flow.
func (h *OIDCHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomState()
	if err != nil {
		h.logger.Err("failed to generate OIDC state: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.states[state] = time.Now().Add(10 * time.Minute)
	h.cleanupExpiredStates()
	h.mu.Unlock()

	authURL := h.oauth2Cfg.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback processes the OIDC callback after authentication.
func (h *OIDCHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state parameter
	state := r.URL.Query().Get("state")
	if state == "" {
		h.logger.Warn("OIDC callback missing state parameter")
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	expiry, ok := h.states[state]
	if ok {
		delete(h.states, state)
	}
	h.mu.Unlock()

	if !ok || time.Now().After(expiry) {
		h.logger.Warn("OIDC callback with invalid or expired state")
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Check for error response from the provider
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.logger.Warn("OIDC provider returned error: %s - %s", errCode, errDesc)
		http.Error(w, fmt.Sprintf("Authentication failed: %s", errDesc), http.StatusUnauthorized)
		return
	}

	// Exchange authorization code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		h.logger.Warn("OIDC callback missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := h.oauth2Cfg.Exchange(r.Context(), code)
	if err != nil {
		h.logger.Err("OIDC token exchange failed: %s", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	// Get user info from the userinfo endpoint
	userInfo, err := h.getUserInfo(r.Context(), token)
	if err != nil {
		h.logger.Err("failed to get OIDC user info: %s", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Create a session
	sessionID, err := generateRandomState()
	if err != nil {
		h.logger.Err("failed to generate session ID: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session := &OIDCSession{
		Email:     userInfo.Email,
		Name:      userInfo.Name,
		ExpiresAt: time.Now().Add(8 * time.Hour),
	}

	h.mu.Lock()
	h.sessions[sessionID] = session
	h.mu.Unlock()

	h.logger.Info("[OIDC] successful login for user: %s (%s)", userInfo.Name, userInfo.Email)

	cookieName := h.config.CookieName
	if cookieName == "" {
		cookieName = "atlantis_oidc"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(8 * time.Hour / time.Second),
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

type oidcUserInfo struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// getUserInfo fetches user information from the OIDC provider's userinfo endpoint.
func (h *OIDCHandler) getUserInfo(ctx context.Context, token *oauth2.Token) (*oidcUserInfo, error) {
	if h.providerCfg.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("provider does not have a userinfo endpoint")
	}

	client := h.oauth2Cfg.Client(ctx, token)
	resp, err := client.Get(h.providerCfg.UserinfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("fetching userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	var info oidcUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding userinfo response: %w", err)
	}

	return &info, nil
}

// IsAuthenticated checks if the request has a valid OIDC session.
func (h *OIDCHandler) IsAuthenticated(r *http.Request) bool {
	cookieName := h.config.CookieName
	if cookieName == "" {
		cookieName = "atlantis_oidc"
	}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}

	h.mu.RLock()
	session, ok := h.sessions[cookie.Value]
	h.mu.RUnlock()

	if !ok {
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		h.mu.Lock()
		delete(h.sessions, cookie.Value)
		h.mu.Unlock()
		return false
	}

	return true
}

// SetSession sets a session for testing purposes.
func (h *OIDCHandler) SetSession(id string, session *OIDCSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions[id] = session
}

// cleanupExpiredStates removes expired state entries. Must be called with lock held.
func (h *OIDCHandler) cleanupExpiredStates() {
	now := time.Now()
	for state, expiry := range h.states {
		if now.After(expiry) {
			delete(h.states, state)
		}
	}
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
