# Builder
FROM golang:latest as builder

# Source
WORKDIR /workspace
COPY . /workspace
RUN go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o raven raven.go




FROM openshift/ubi-init:latest

ENV CERT_FILE=/mg/secret/ssc/tls.crt \
    CLONE_PATH=/tmp/clone \
    VAULT_TOKEN="" \
    VAULT_KV="" \
    REPO_URL=""\ 
    SSL_CERT_FILE=/tmp/cert/ca.crt
    


COPY --from=builder /workspace/files/start /start
COPY --from=builder /workspace/raven /raven
USER 1001
ENTRYPOINT ["/start"]