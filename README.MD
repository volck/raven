# Raven

[Raven](https://volck.github.io/raven) is a tool that transform and reconciles secrets stored in [Vault](https://www.vaultproject.io/) to [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) stored in a Git repository. 

Raven will keep a repository eventually consistent by iterating a path in Vault:

*  Creating a sealed secret in a given git repository
*  Cleaning out "old" secrets from git when removed from Vault.

This allows us to make secrets a declarative state and we can publish them...anywhere.. which in Raven is GIT.

Raven can run as a stand alone application, but will require [kubeseal](https://github.com/bitnami-labs/sealed-secrets#overview). Raven can also run as a dockerized application, but will require the operator to translate a sealed secreet to a normal kubernetes secret.


## Authors

* [Lars Erik Thorsplass](https://github.com/laetho)
* [Emil Volckmar Ry](https://github.com/volck)
