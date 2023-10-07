package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	projectAccessTokenPath        = "projectaccesstoken/"
	pathProjectAccessTokenHelpSyn = `
	Generate a rollbar project access token from a role.
	`
	pathProjectAccessTokenDesc = `
	This path generates a rollbar access token based on a particular role.
	`
)

func pathProjectAccessToken(b *RollbarBackend) *framework.Path {
	return &framework.Path{
		Pattern: projectAccessTokenPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathProjectAccessTokenRead,
			logical.UpdateOperation: b.pathProjectAccessTokenRead,
		},
		HelpSynopsis:    pathProjectAccessTokenHelpSyn,
		HelpDescription: pathProjectAccessTokenDesc,
	}
}

func (b *RollbarBackend) pathProjectAccessTokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	uuid, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("error generating UUID for project access token name: %w", err)
	}
	patName := roleName + "-" + uuid

	pat, err := createProjectAccessToken(ctx, client, roleEntry.ProjectAccessTokenScopes, roleEntry.ProjectID, patName)
	if err != nil || pat == nil || len(*pat) == 0 {
		return nil, fmt.Errorf("error creating project access token: %w", err)
	}

	resp := b.Secret(rollbarProjectAccessTokenType).Response(map[string]interface{}{
		"project_access_token": *pat,
	}, map[string]interface{}{
		"project_access_token": *pat,
		"role":                 roleEntry.Name,
	})

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}

	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
