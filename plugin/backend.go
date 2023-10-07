package plugin

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var Version = "v1"

// RollbarBackend defines a struct that extends the Vault backend
// and stores the rollbar API Client
type RollbarBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *rollbarClient
}

// backendHelp defines the helptext for the rollbar backend
const backendHelp = `
The rollbar secrets backend allows for the dynamic generation of 
rollbar access token. After mounting this backend, credentials to 
interact with the rollbar API must be configured with the /config 
endpoints.
`

// Factory returns a new rollbar backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// newBackend returns a new rollbarBackend and sets up the paths it will handle and
// secrets it will store
func newBackend() *RollbarBackend {

	var b = RollbarBackend{}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathProjectAccessToken(&b),
				// API does't offer a route to rotate account access tokens
				// pathConfigRotate(&b),
			},
		),
		Secrets: []*framework.Secret{
			b.rollbarProjectAccessToken(),
		},
		BackendType:    logical.TypeLogical,
		Invalidate:     b.invalidate,
		RunningVersion: Version,
	}

	return &b
}

// reset clears the rollbar client config for a new backend to be configured
func (b *RollbarBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing rollbar client configuration within the backend
func (b *RollbarBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the rollbar backend as it configures and creates a new
// rollbar API client
func (b *RollbarBackend) getClient(ctx context.Context, s logical.Storage) (*rollbarClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(RollbarConfig)
	}

	b.client, err = NewClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}
