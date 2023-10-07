package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathRoleDef             = "roles/"
	pathRoleHelpSynopsis    = "Manages the Vault role for generating rollbar project access tokens."
	pathRoleHelpDescription = `
	This path allows you to read and write roles used to generate rollbar project access tokens.
	You can configure scopes associated with project access tokens by providing a list of scopes with the 
	input data.
	`
	pathRoleListHelpSynopsis    = "List the existing roles in rollbar backend"
	pathRoleListHelpDescription = "Roles will be listed by the role name."
	defaultMaxTTL               = time.Second * 7200
	defaultTTL                  = time.Second * 3600
)

// var (
// 	projectAccessTokenScopes = []string{
// 		"read",
// 		"write",
// 		"post_client_item",
// 		"post_server_item",
// 	}
// )

// RollbarRoleEntry defines the data associated with
// a Vault role for interoperating with the rollbar
// api
type RollbarRoleEntry struct {
	Name                     string        `json:"name"`
	ProjectID                int           `json:"project_id"`
	ProjectAccessTokenScopes string        `json:"project_access_token_scopes"`
	TTL                      time.Duration `json:"ttl"`
	MaxTTL                   time.Duration `json:"max_ttl"`
}

func pathRole(b *RollbarBackend) []*framework.Path {

	return []*framework.Path{
		{
			Pattern: pathRoleDef + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Required. Name of the role",
					Required:    true,
				},
				"project_id": {
					Type:        framework.TypeInt,
					Description: "Required. Rollbar project ID",
					Required:    true,
				},
				"project_access_token_scopes": {
					Type:        framework.TypeString,
					Description: "Optional, List of project scopes to be applied to the access token",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Optional, Default least time for the generated project access token. If not set or set to 0, system default will be used.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Optional. Maximum lease time for role. If not set or set to 0, system default will be used.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
			ExistenceCheck:  b.PathRolesExistenceCheck,
		},
		{
			Pattern: pathRoleDef + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// pathRolesList lists the rollbar roleEntries
func (b *RollbarBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entries, err := req.Storage.List(ctx, pathRoleDef)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead returns a specifc rollbar roleEntry
func (b *RollbarBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

// pathRolesWrite creates or updates a rollbar roleEntry
func (b *RollbarBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	projectID, ok := d.Get("project_id").(int)
	if !ok || projectID == 0 {
		return logical.ErrorResponse("missing project ID"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &RollbarRoleEntry{
			TTL:    defaultTTL,
			MaxTTL: defaultMaxTTL,
		}
	}

	roleEntry.Name = name
	roleEntry.ProjectID = projectID

	createOperation := (req.Operation == logical.CreateOperation)

	if scopes, ok := d.GetOk("project_access_token_scopes"); ok {
		roleEntry.ProjectAccessTokenScopes = scopes.(string)
		// check validity of provided scopes
		// for _, scope := range roleEntry.ProjectAccessTokenScopes {
		// 	valid := contains(projectAccessTokenScopes, scope)
		// 	if !valid {
		// 		return nil, fmt.Errorf("provided scope %s is not a valid rollbar project access token scope", scope)
		// 	}
		// }
	} else if createOperation {
		roleEntry.ProjectAccessTokenScopes = d.Get("project_access_token_scopes").(string)
		// check validity of provided scopes
		// for _, scope := range roleEntry.ProjectAccessTokenScopes {
		// 	valid := contains(projectAccessTokenScopes, scope)
		// 	if !valid {
		// 		return nil, fmt.Errorf("provided scope %s is not a valid rollbar project access token scope", scope)
		// 	}
		// }
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name, roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRolesDelete deletes a rollbar roleEntry
func (b *RollbarBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	err := req.Storage.Delete(ctx, pathRoleDef+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting rollbar role: %w", err)
	}

	return nil, nil
}

func (b *RollbarBackend) PathRolesExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {

	out, err := req.Storage.Get(ctx, pathRoleDef)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

// getRole gets the role from the Vault storage API
func (b *RollbarBackend) getRole(ctx context.Context, s logical.Storage, name string) (*RollbarRoleEntry, error) {

	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, pathRoleDef+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role RollbarRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

// setRole sets the role into the Vault storage API
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *RollbarRoleEntry) error {

	entry, err := logical.StorageEntryJSON(pathRoleDef+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// // validateScopes TODO implement me...
// func validateScopes(scopes any) error {

// 	return nil
// }

// toResponseData returns response data for a rollbar role entry
func (r *RollbarRoleEntry) toResponseData() map[string]interface{} {

	return map[string]interface{}{
		"project_id":                  r.ProjectID,
		"project_access_token_scopes": r.ProjectAccessTokenScopes,
		"ttl":                         r.TTL.Seconds(),
		"max_ttl":                     r.MaxTTL.Seconds(),
	}
}
