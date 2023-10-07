package plugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rollbarProjectAccessTokenType = "rollbar_project_access_token"
)

func (b *RollbarBackend) rollbarProjectAccessToken() *framework.Secret {

	return &framework.Secret{
		Type: rollbarProjectAccessTokenType,
		Fields: map[string]*framework.FieldSchema{
			"project_access_token": {
				Type:        framework.TypeString,
				Description: "Rollbar Project Access Token",
			},
		},
		Renew:  b.projectAccessTokenRenew,
		Revoke: b.projectAccessTokenRevoke,
	}
}

func (b *RollbarBackend) projectAccessTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}
	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}

func (b *RollbarBackend) projectAccessTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	pat := ""
	patRaw, ok := req.Secret.InternalData["project_access_token"]
	if ok {
		pat, ok = patRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for project access token in secret internal data")
		}
	}

	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if err := deleteProjectAccessToken(ctx, client, roleEntry.ProjectID, pat); err != nil {
		return nil, fmt.Errorf("error revoking project access token: %w", err)
	}
	return nil, nil
}

func createProjectAccessToken(ctx context.Context, c *rollbarClient, scopes string, projectID int, name string) (*string, error) {
	return c.CreateProjectAccessToken(ctx, scopes, projectID, name)
}

func deleteProjectAccessToken(ctx context.Context, c *rollbarClient, projectID int, pat string) error {
	return c.deleteProjectAccessToken(ctx, projectID, pat)
}
