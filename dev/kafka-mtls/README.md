# Kafka mTLS

Minimal setup to test Kafka mTLS connections with.

## Usage

```shell
make
docker compose up -d
```

The broker's SSL listener is exposed to `localhost:9093`.

Use `certs/ca-cert.pem`, `certs/client-cert.pem`, and `certs/client-key.pem`
in your client configuration. 