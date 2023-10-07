package plugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathConfigDef             = "config"
	configStoragePath         = "config"
	pathConfigHelpSynopsis    = "Configure the rollbar backend"
	pathConfigHelpDescription = `
	The rollbar secret backend requires credentials for managing
	project access tokens.

	You must provide a read, write scoped account access token.
	`
)

type RollbarConfig struct {
	AccountAccessToken string `json:"account_access_token"`
}

func pathConfig(b *RollbarBackend) *framework.Path {

	return &framework.Path{
		Pattern: pathConfigDef,
		Fields: map[string]*framework.FieldSchema{
			"account_access_token": {
				Type:        framework.TypeString,
				Description: "The Account Access Token for access Rollbar's API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Account Access Token",
					Sensitive: true,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.PathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *RollbarBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account_access_token": config.AccountAccessToken,
		},
	}, nil
}

func (b *RollbarBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(RollbarConfig)
	}

	if accountAccessToken, ok := data.GetOk("account_access_token"); ok {
		config.AccountAccessToken = accountAccessToken.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing Account Access Token in configuration")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *RollbarBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func (b *RollbarBackend) PathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {

	out, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*RollbarConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(RollbarConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}
