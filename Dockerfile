FROM docker.io/alpine:latest 

ENV CERT_FILE=/mg/secret/ssc/tls.crt \
    CLONE_PATH=/tmp/clone \
    VAULT_TOKEN="" \
    VAULT_KV="" \
    REPO_URL=""\ 
    SSL_CERT_FILE=/tmp/cert/ca.crt
    
COPY . /
USER 1001
ENTRYPOINT ["/start"]
