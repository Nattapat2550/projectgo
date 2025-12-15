package handlers

import (
  "bytes"
  "context"
  "encoding/json"
  "errors"
  "net/http"
  "net/url"
  "strings"

  "projectgob-backend/internal/config"
)

// Minimal Google OAuth implementation (no heavy deps):
// - Web: redirect -> callback (authorization_code)
// - Mobile: exchange authCode with redirect_uri=postmessage (same as Node)

type GoogleOAuth struct {
  clientID     string
  clientSecret string
  callbackURI  string
}

type googleUserInfo struct {
  ID      string `json:"id"`
  Email   string `json:"email"`
  Name    string `json:"name"`
  Picture string `json:"picture"`
}

func NewGoogleOAuth(cfg config.Config) *GoogleOAuth {
  return &GoogleOAuth{
    clientID:     strings.TrimSpace(cfg.GoogleClientID),
    clientSecret: strings.TrimSpace(cfg.GoogleClientSecret),
    callbackURI:  strings.TrimSpace(cfg.GoogleCallbackURI),
  }
}

func (g *GoogleOAuth) configured() bool {
  return g.clientID != "" && g.clientSecret != "" && g.callbackURI != ""
}

// AuthURL generates the Google OAuth consent URL (same scopes/params as the old Node backend).
func (g *GoogleOAuth) AuthURL(state string) (string, bool) {
  if !g.configured() {
    return "", false
  }
  q := url.Values{}
  q.Set("client_id", g.clientID)
  q.Set("redirect_uri", g.callbackURI)
  q.Set("response_type", "code")
  q.Set("scope", "openid email profile")
  q.Set("access_type", "offline")
  q.Set("prompt", "consent")
  if strings.TrimSpace(state) != "" {
    q.Set("state", state)
  }
  return "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode(), true
}

// ExchangeWeb exchanges an authorization code from the web redirect callback.
func (g *GoogleOAuth) ExchangeWeb(ctx context.Context, code string) (*googleUserInfo, error) {
  if !g.configured() {
    return nil, errors.New("google auth not configured")
  }
  tok, err := exchangeAuthCode(ctx, g.clientID, g.clientSecret, code, g.callbackURI)
  if err != nil {
    return nil, err
  }
  return fetchGoogleUserInfo(ctx, tok.AccessToken)
}

// ExchangeMobile exchanges an authCode from mobile (Flutter) flow.
// This matches the Node logic: redirect_uri = 'postmessage'.
func (g *GoogleOAuth) ExchangeMobile(ctx context.Context, authCode string) (*googleUserInfo, error) {
  if g.clientID == "" || g.clientSecret == "" {
    return nil, errors.New("google auth not configured")
  }
  tok, err := exchangeAuthCode(ctx, g.clientID, g.clientSecret, authCode, "postmessage")
  if err != nil {
    return nil, err
  }
  return fetchGoogleUserInfo(ctx, tok.AccessToken)
}

type tokenResponse struct {
  AccessToken string `json:"access_token"`
  TokenType   string `json:"token_type"`
  ExpiresIn   int    `json:"expires_in"`
  IdToken     string `json:"id_token"`
}

func exchangeAuthCode(ctx context.Context, clientID, clientSecret, code, redirectURI string) (*tokenResponse, error) {
  form := url.Values{}
  form.Set("code", strings.TrimSpace(code))
  form.Set("client_id", clientID)
  form.Set("client_secret", clientSecret)
  form.Set("redirect_uri", redirectURI)
  form.Set("grant_type", "authorization_code")

  req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

  resp, err := http.DefaultClient.Do(req)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()

  var tr tokenResponse
  if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
    return nil, err
  }
  if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    // best-effort include error payload
    b, _ := json.Marshal(tr)
    return nil, errors.New("google token exchange failed: " + string(bytes.TrimSpace(b)))
  }
  if strings.TrimSpace(tr.AccessToken) == "" {
    return nil, errors.New("google token exchange failed: no access_token")
  }
  return &tr, nil
}

func fetchGoogleUserInfo(ctx context.Context, accessToken string) (*googleUserInfo, error) {
  req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
  req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))

  resp, err := http.DefaultClient.Do(req)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()

  var info googleUserInfo
  if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
    return nil, err
  }
  if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    return nil, errors.New("google userinfo failed")
  }
  info.Email = strings.TrimSpace(info.Email)
  return &info, nil
}
