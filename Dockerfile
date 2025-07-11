FROM alpine:3.21.3

RUN apk --no-cache add coreutils util-linux-misc bash curl jq github-cli

# Download and install latest version of vault
RUN curl -L -o /tmp/vault.zip https://releases.hashicorp.com/vault/1.12.2/vault_1.12.2_linux_amd64.zip \
  && unzip /tmp/vault.zip -d /usr/local/bin/ \
  && rm -f /tmp/vault.zip

COPY bin/setenv.py /usr/local/bin/setenv.py

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]