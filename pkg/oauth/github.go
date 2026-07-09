// Package oauth implements the OAuth 2.0 sign-in providers for the DevRadar UI.
// A provider's only job is to turn an authorization code into a proven identity
// — a stable per-user subject plus a provider-verified email. The rest of the
// sign-in flow (tenant resolution, session minting) is provider-agnostic and
// lives in pkg/tenant and pkg/server; adding a provider means adding a type here
// that yields an Identity, nothing more.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// ErrNoVerifiedEmail is returned when the provider account has no primary,
// verified email. DevRadar keys tenants on a verified email, so an unverified
// account cannot be trusted to sign in (an attacker could set an unverified
// address to someone else's and hijack their tenant). The caller surfaces this
// to the user as "verify your email with the provider, or use the email link".
var ErrNoVerifiedEmail = errors.New("no primary verified email on provider account")

// Identity is the proven result of an OAuth exchange: a provider-stable subject
// and a verified email. Both are trusted inputs to tenant.ResolveByIdentity.
type Identity struct {
	Provider  string // e.g. tenant.ProviderGitHub
	Subject   string // provider's immutable user id (GitHub: numeric id as text)
	Email     string // primary, provider-verified email
	AvatarURL string // optional profile image URL (cosmetic; may be "")
}

// githubEndpoint is GitHub's OAuth 2.0 endpoint. Inlined (two constants) rather
// than importing golang.org/x/oauth2/github, which is not vendored and would add
// a dependency for two URLs.
var githubEndpoint = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

// defaultGitHubAPIBase is the GitHub REST API base. It is a field on GitHub so
// tests can point it at an httptest.Server and avoid the network.
const defaultGitHubAPIBase = "https://api.github.com"

// GitHub is the GitHub OAuth provider. Construct with NewGitHub.
type GitHub struct {
	cfg     *oauth2.Config
	apiBase string
}

// NewGitHub builds a GitHub provider. clientID/clientSecret come from the
// GITHUB_OAUTH_CLIENT_ID / GITHUB_OAUTH_CLIENT_SECRET secrets; redirectURL is
// derived from BASE_URL. Scopes read:user + user:email are the minimum needed to
// read the numeric user id and the verified email list.
func NewGitHub(clientID, clientSecret, redirectURL string) *GitHub {
	return &GitHub{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     githubEndpoint,
			Scopes:       []string{"read:user", "user:email"},
		},
		apiBase: defaultGitHubAPIBase,
	}
}

// AuthCodeURL returns the provider authorize URL to redirect the user to. state
// is an opaque anti-CSRF value the caller binds to the browser and re-checks on
// callback.
func (g *GitHub) AuthCodeURL(state string) string {
	return g.cfg.AuthCodeURL(state)
}

// Exchange completes the OAuth flow: it swaps the authorization code for an
// access token, then reads the account's numeric id and primary verified email.
// Returns ErrNoVerifiedEmail if the account has no primary verified address.
func (g *GitHub) Exchange(ctx context.Context, code string) (*Identity, error) {
	tok, err := g.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}
	client := g.cfg.Client(ctx, tok)

	id, avatar, err := g.userProfile(ctx, client)
	if err != nil {
		return nil, err
	}
	email, err := g.primaryVerifiedEmail(ctx, client)
	if err != nil {
		return nil, err
	}
	return &Identity{Provider: "github", Subject: id, Email: email, AvatarURL: avatar}, nil
}

// userProfile fetches the account's immutable numeric id (the stable subject,
// not the renamable login) and its avatar URL via GET /user.
func (g *GitHub) userProfile(ctx context.Context, client *http.Client) (id, avatarURL string, err error) {
	var u struct {
		ID        int64  `json:"id"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := getJSON(ctx, client, g.apiBase+"/user", &u); err != nil {
		return "", "", fmt.Errorf("github get user: %w", err)
	}
	if u.ID == 0 {
		return "", "", errors.New("github user id missing")
	}
	return fmt.Sprintf("%d", u.ID), u.AvatarURL, nil
}

// primaryVerifiedEmail returns the account's primary, verified email. The
// profile's top-level email field is unreliable (may be null or unverified), so
// GET /user/emails is authoritative. Only a primary AND verified address is
// accepted.
func (g *GitHub) primaryVerifiedEmail(ctx context.Context, client *http.Client) (string, error) {
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, client, g.apiBase+"/user/emails", &emails); err != nil {
		return "", fmt.Errorf("github get emails: %w", err)
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", ErrNoVerifiedEmail
}

// getJSON performs a GET and decodes a 2xx JSON body into out. GitHub wants an
// explicit Accept header for the stable v3 API.
func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
