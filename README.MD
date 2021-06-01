# Raven

Raven is a tool that transform and reconciles secrets stored in [Vault](https://www.vaultproject.io/) to [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) stored in a Git repository. 

Raven will keep a repository eventually consistent by iterating a path in Vault:
*  Creating a sealed secret in a given git repository
*  Cleaning out "old" secrets from git when removed from Vault.

This allows us to make secrets a declarative state and we can publish them...anywhere.. which in Raven is GIT.

Raven can run as a stand alone application, but will require [kubeseal](https://github.com/bitnami-labs/sealed-secrets#overview). Raven can also run as a dockerized application, but will require the operator to translate a sealed secreet to a normal kubernetes secret.

## Design

```mermaid
graph LR
  Vault[(Vault)]
  Git[(Git Repo)]
  raven[[Raven]]
  
  
  raven -->|Read<br>Secrets| Vault
  raven -->|Write<br>SealedSecrets| Git
```

### Inner workings of Raven

```mermaid
graph TD
    B(Validate Token)
    B -->|Invalid token| D[sys.exit]
    B -->|Valid token| C{Grab list from Vault}
    C -->|Validate token| B
    C -->|No changes, sleep for a while and grab new list|C
    C -->|Change detected| E[Make/delete sealed secret]
    E -->F[Push to git]
```


## Usage:

```
Usage of ./raven:
  -cert string
        used to create sealed secrets
  -clonepath string
        Path in which to clone repo and used for base for appending keys. (default "/tmp/clone")
  -dest string
        destination env in git repository to output SealedSecrets to.
  -repourl string
        REPO url. e.g. https://uname:pwd@src_control/some/path/somerepo.git / but also supports ssh://user@repostorage/git/somerepo.git
  -se string
        specifies secret engine to grab secrets from in Vault.
  -token string
        token used for to grab secrets from Vault
  -vaultendpoint string
        URL to the Vault installation.
```

in addition to this, Raven also supports generic webhooks by setting the webhook_url environment-variable. The function is called after every commit. 

```bash=
export webhook_url=https://some.url/
```

## Example of a Raven invocation

```bash=
./raven \
-se=test \ 
-cert=cert.crt \ 
-token=s.omeverysecrettoken \ 
-clonepath=/t/place/to/be \ 
-dest=test \ 
-repourl=ssh://user@repostorage/git/somerepo.git \ 
-vaultendpoint=https://my.vault/ 
```

## Authors & credits

* [Lars Erik Thorsplass](https://github.com/laetho)
* [Emil Volckmar Ry](https://github.com/volck)
* My employer, Norsk Tipping
