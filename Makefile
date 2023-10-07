GOARCH = arm64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt  build  test start 

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-secrets-rollbar cmd/vault-plugin-secrets-rollbar/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins -log-level=DEBUG -dev-listen-address="127.0.0.1:8200"

test:
	go test -v ./...

enable:
	VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable -path=rollbar vault-plugin-secrets-rollbar

clean:
	rm -f ./vault/plugins/vault-plugin-secrets-rollbar

fmt:
	go fmt $$(go list ./...)

setup:	enable
	VAULT_ADDR=http://127.0.0.1:8200 vault write rollbar/config  account_access_token=${ACCOUNT_ACCESS_TOKEN}
	VAULT_ADDR=http://127.0.0.1:8200 vault write rollbar/roles/test project_access_token_scopes=read max_ttl=3h ttl=2h
	VAULT_ADDR=http://127.0.0.1:8200 vault read rollbar/roles/test

.PHONY: build clean fmt start  enable test setup
