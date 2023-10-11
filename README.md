# vault-plugin-secrets-rollbar

```sh
vault write rollbar/config \
    account_access_token=$ACCOUNT_ACCESS_TOKEN
```

```sh
$ vault write rollbar/roles/test \
    project_id=$PROJECT_ID \
    project_access_token_scopes=post_client_item,post_server_item,read,write \
    ttl=1h \
    max_ttl=3h
```

```sh
$ vault list rollbar/roles
```

```sh
$ vault list rollbar/roles
```

```sh
$ vault read rollbar/roles/test
Key                Value
---                -----
lease_id           rollbar/test/DCDdWYBROZRIQQfmOv2C4SUP
lease_duration     2h
lease_renewable    true
access_key         <REDACTED for GitHub>
```

```sh
$ vault lease renew rollbar/test/DCDdWYBROZRIQQfmOv2C4SUP
```

```sh
$ vault lease revoke rollbar/test/DCDdWYBROZRIQQfmOv2C4SUP
```

```sh
$ vault lease revoke -prefix rollbar/
```

