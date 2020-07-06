package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

const g5AuthHostname = "auth.g5search.com"

type g5User struct {
	Email string   `json:"email"`
	Roles []g5Role `json:"roles"`
}

type g5Role struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type G5Provider struct {
	*ProviderData

	allowedRoles []string
}

func NewG5Provider(p *ProviderData) *G5Provider {
	p.ProviderName = "G5"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   g5AuthHostname,
			Path:   "/oauth/authorize"}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   g5AuthHostname,
			Path:   "/oauth/token"}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   g5AuthHostname,
			Path:   "/v1/me",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	return &G5Provider{ProviderData: p}
}

func (p *G5Provider) SetAllowedRoles(allowedRoles []string) {
	p.allowedRoles = allowedRoles
}

func (p *G5Provider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		p.ProfileURL.String()+"?access_token="+s.AccessToken,
		nil,
	)
	if err != nil {
		return "", err
	}

	user := &g5User{}
	if err := requests.RequestJSON(req, user); err != nil {
		return "", err
	}

	if user.Email == "" {
		return "", fmt.Errorf("can't determine email address")
	}

	hasAllowedRole, err := p.hasAllowedRole(user)
	if err != nil {
		return "", fmt.Errorf("validating roles of user '%s': %v", user.Email, err)
	}
	if !hasAllowedRole {
		return "", fmt.Errorf("user '%s' doesn't have any of the required roles", user.Email)
	}

	return user.Email, nil
}

func (p *G5Provider) hasAllowedRole(user *g5User) (bool, error) {
	for _, role := range user.Roles {
		if role.Type == "GLOBAL" {
			for _, allowed := range p.allowedRoles {
				if allowed == role.Name {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
