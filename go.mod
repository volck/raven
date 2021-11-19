module github.com/volck/raven

go 1.16

require (
	github.com/bitnami-labs/sealed-secrets v0.12.4
	github.com/containerd/containerd v1.4.12 // indirect
	github.com/go-git/go-git/v5 v5.2.0
	github.com/hashicorp/vault v1.7.5
	github.com/hashicorp/vault-plugin-secrets-kv v0.8.0
	github.com/hashicorp/vault/api v1.0.5-0.20210210214158-405eced08457
	github.com/hashicorp/vault/sdk v0.2.1-0.20210927220619-d41fb44977e1
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.0.0-rc95 // indirect
	github.com/sirupsen/logrus v1.7.0
	go.mongodb.org/mongo-driver v1.5.1 // indirect
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
)
