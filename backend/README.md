# CSR Generator — Backend

Spring Boot 3 + Java 21 + Bouncy Castle. Generates key pairs and PKCS#10 CSRs.

See [../BACKEND_PLAN.md](../BACKEND_PLAN.md) for the full design.

## Run

```bash
mvn spring-boot:run
```

Starts on `http://localhost:8080`.

## Build

```bash
mvn clean package
java -jar target/csr-generator-0.1.0.jar
```

## API

### `POST /api/v1/csr` — generate key pair + CSR

```bash
curl -s http://localhost:8080/api/v1/csr \
  -H 'Content-Type: application/json' \
  -d '{
    "keyAlgorithm": "RSA",
    "keySize": 2048,
    "subject": {
      "commonName": "example.com",
      "organization": "Example Inc",
      "country": "US"
    },
    "subjectAltNames": [
      { "type": "DNS", "value": "example.com" },
      { "type": "DNS", "value": "www.example.com" }
    ]
  }'
```

Returns CSR PEM, public key PEM, private key PEM, and the algorithms used.

> **Note:** private key is returned in the response for this dev milestone only.
> Production must keep keys in a KMS/HSM — see the plan's security section.

### `POST /api/v1/csr/parse` — decode a CSR

```bash
curl -s http://localhost:8080/api/v1/csr/parse \
  -H 'Content-Type: application/json' \
  -d '{"pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"}'
```

Returns subject DN + fields, SANs, key algorithm/size, signature algorithm, and
whether the CSR self-signature verifies.

### `POST /api/v1/csr/validate` — policy + integrity check

Same body as `/parse`. Returns `{ valid, errors[], warnings[] }`. Checks signature
validity, CN presence, weak signature algorithms, RSA key strength, and SAN presence.

### `POST /api/v1/convert` — PEM ↔ DER

```bash
# PEM -> DER (returns base64 DER)
curl -s http://localhost:8080/api/v1/convert -H 'Content-Type: application/json' \
  -d '{"from":"PEM","to":"DER","pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n"}'

# DER -> PEM (needs pemType, e.g. "CERTIFICATE REQUEST", "CERTIFICATE", "PUBLIC KEY")
curl -s http://localhost:8080/api/v1/convert -H 'Content-Type: application/json' \
  -d '{"from":"DER","to":"PEM","derBase64":"MIIC...","pemType":"CERTIFICATE REQUEST"}'
```

### `POST /api/v1/convert/pkcs12` — bundle cert + key into .p12

```bash
curl -s http://localhost:8080/api/v1/convert/pkcs12 -H 'Content-Type: application/json' \
  -d '{"certificatePem":"...","privateKeyPem":"...","caChainPem":["..."],"alias":"mykey","password":"changeit"}' \
  -o bundle.p12
```

Returns the binary PKCS#12 as a file download.

## Supported

- `keyAlgorithm`: `RSA` (2048/3072/4096), `EC` (P-256/P-384/P-521), `ED25519`
- SAN types: `DNS`, `IP`, `EMAIL`, `URI`

## Status

Milestones 1–4 done: skeleton + keygen + CSR generation + parse/validate + PEM/DER/PKCS#12
conversion. Next: persistence + audit log, auth + TLS, KMS/HSM key storage, self-signed
cert issuance, optional ACME/DigiCert CA submission.
