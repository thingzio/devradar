// Package oauth implements the minimal GitHub OAuth flow DevRadar's UI uses to
// authenticate a human so they can mint API tokens. It is intentionally small:
// authorize URL, code exchange, and a /user lookup. No SDK.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds GitHub OAuth app credentials and the callback URL.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// GitHubUser is the subset of the GitHub /user response we persist.
type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// AuthCodeURL builds the GitHub authorize URL with the given opaque state.
func (c *Config) AuthCodeURL(state string) string {
	v := url.Values{}
	v.Set("client_id", c.ClientID)
	v.Set("redirect_uri", c.RedirectURL)
	v.Set("scope", "read:user user:email")
	v.Set("state", state)
	return "https://github.com/login/oauth/authorize?" + v.Encode()
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Exchange trades an authorization code for an access token.
func (c *Config) Exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("token exchange decode: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token exchange: no access_token (%s)", out.Error)
	}
	return out.AccessToken, nil
}

// User fetches the authenticated user's profile, falling back to the primary
// verified email if the profile email is private.
func (c *Config) User(ctx context.Context, token string) (*GitHubUser, error) {
	u, err := c.get(ctx, token, "https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	var gu GitHubUser
	if err := json.Unmarshal(u, &gu); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	if gu.Email == "" {
		gu.Email = c.primaryEmail(ctx, token)
	}
	return &gu, nil
}

func (c *Config) primaryEmail(ctx context.Context, token string) string {
	b, err := c.get(ctx, token, "https://api.github.com/user/emails")
	if err != nil {
		return ""
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(b, &emails); err != nil {
		return ""
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	return ""
}

func (c *Config) get(ctx context.Context, token, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github get: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github get %s: status %d", u, resp.StatusCode)
	}
	return body, nil
}
