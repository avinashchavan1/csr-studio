# CSR Generator — Java Backend Plan

A reference document for building the backend of a CSR (Certificate Signing Request) generator and certificate-handling service in Java.

---

## 1. What the backend must do

| Capability | Description |
|------------|-------------|
| Key pair generation | Generate RSA / ECDSA / EdDSA key pairs server-side or accept a CSR generated client-side |
| CSR generation | Build a PKCS#10 CSR from subject DN + SANs + key usage + extensions |
| CSR parsing / validation | Decode an uploaded CSR, verify signature, extract subject, SANs, key strength |
| Key storage | Store private keys securely (HSM / KMS / encrypted DB) — never plaintext |
| (Optional) Self-signed cert | Issue a self-signed X.509 cert for testing / internal CA |
| (Optional) CA submission | Submit CSR to a public CA via ACME or REST API and retrieve issued cert |
| Format conversion | PEM ↔ DER, PKCS#12 (.pfx) bundling, PKCS#8 key encoding |
| Validation rules | Enforce min key size (RSA ≥ 2048, EC P-256+), allowed algos, SAN policy |

---

## 2. What real CAs / cert tooling use under the hood

This is the important part — what the industry actually relies on.

### Bouncy Castle (the de-facto standard)
- **The** cryptography library for almost all serious Java certificate work.
- Used widely across the PKI ecosystem (EJBCA, Keyfactor, Dogtag/Red Hat CA, Apache, Eclipse projects, and many commercial CA stacks build on it).
- Provides the full PKI alphabet soup: PKCS#10 (CSR), X.509 v3, PKCS#7/CMS, PKCS#8, PKCS#12, OCSP, CRL, CMP, EST, TSP (timestamping).
- Two flavors:
  - `bcprov` — the JCE provider (algorithms).
  - `bcpkix` — the PKI/CMS layer (CSR, cert, OCSP builders). **This is what you build CSRs with.**
- Maven (use latest `jdk18on` artifacts):
  ```xml
  <dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.78.1</version>
  </dependency>
  <dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk18on</artifactId>
    <version>1.78.1</version>
  </dependency>
  ```

### EJBCA (Keyfactor) — reference for "real CA" architecture
- Open-source enterprise CA written in Java, used by governments and large enterprises.
- Built on Bouncy Castle + Java EE. Good architecture reference even if you don't run it.
- Worth studying for: certificate profiles, validation rules, HSM integration patterns.

### ACME protocol (how DigiCert / Let's Encrypt automate issuance)
- DigiCert, Let's Encrypt, ZeroSSL, Sectigo all expose ACME (RFC 8555) for automated issuance.
- Java client library: **acme4j** (`org.shredzone.acme4j`). Handles account registration, order, challenge (HTTP-01 / DNS-01), CSR finalize, cert download.
  ```xml
  <dependency>
    <groupId>org.shredzone.acme4j</groupId>
    <artifactId>acme4j-client</artifactId>
    <version>3.4.0</version>
  </dependency>
  ```
- If integrating directly with DigiCert's commercial API instead of ACME, use their CertCentral REST API over plain HTTP client.

### HSM / key protection (what CAs use to guard private keys)
- CAs never keep CA private keys on disk. They use HSMs via **PKCS#11**.
- Java access via the built-in **SunPKCS11** provider, or vendor SDKs (Thales Luna, AWS CloudHSM, Utimaco, nCipher/Entrust).
- Cloud equivalent: **AWS KMS**, **GCP Cloud KMS**, **Azure Key Vault** — generate/sign without key ever leaving the service.
- For an app (not a CA), KMS/Key Vault is usually the right call — managed, auditable, no HSM ops.

### Summary recommendation
> Use **Bouncy Castle (bcpkix)** for all CSR/cert generation and parsing. Use **acme4j** if you submit to public CAs. Use **cloud KMS or PKCS#11 HSM** for private key protection. This mirrors how DigiCert/Let's Encrypt/EJBCA-based stacks are built.

---

## 3. Tech stack

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | Java 21 (LTS) | Records, pattern matching, virtual threads |
| Framework | Spring Boot 3.x | REST API, validation, security |
| Crypto | Bouncy Castle 1.78+ (`bcpkix-jdk18on`) | CSR / X.509 / PKCS#12 |
| CA submission | acme4j 3.x (optional) | ACME automated issuance |
| Key storage | AWS KMS / Azure Key Vault / PKCS#11 HSM | No plaintext keys |
| Persistence | PostgreSQL | Metadata, audit log, cert records |
| DB access | Spring Data JPA / jOOQ | |
| Build | Maven or Gradle | |
| Auth | Spring Security + OAuth2 / JWT | Protect endpoints |
| Audit | Structured logging + DB audit table | Every key/cert op logged |

---

## 4. Module / package layout

```
com.example.csrgen
├── api/                 REST controllers (CSR, cert, key endpoints)
│   ├── dto/             request/response records
│   └── error/           exception handlers
├── domain/              core models (Subject, SanEntry, KeySpec, CsrRequest)
├── crypto/
│   ├── KeyPairService       generate RSA/EC/EdDSA key pairs
│   ├── CsrService           build & parse PKCS#10 (Bouncy Castle)
│   ├── CertService          self-signed / parse X.509
│   ├── ConversionService    PEM <-> DER, PKCS#12 bundling
│   └── ValidationService    key size, algo, SAN policy enforcement
├── ca/                  optional CA integration
│   ├── AcmeClient           acme4j wrapper
│   └── DigicertClient       CertCentral REST (if used)
├── keystore/            KMS / HSM / PKCS#11 abstraction
│   └── KeyVaultService
├── persistence/         JPA entities + repositories
├── security/            authn/authz config
└── config/              Bouncy Castle provider registration, beans
```

---

## 5. Core REST API (draft)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/keys` | Generate a key pair (returns key id; private key stays in vault) |
| POST | `/api/v1/csr` | Generate a CSR from subject + SAN + key id (or inline key) |
| POST | `/api/v1/csr/parse` | Parse + validate an uploaded CSR, return decoded fields |
| POST | `/api/v1/csr/validate` | Run policy checks without storing |
| POST | `/api/v1/cert/self-signed` | Issue a self-signed cert (test/internal) |
| POST | `/api/v1/cert/convert` | Convert between PEM/DER/PKCS#12 |
| POST | `/api/v1/ca/submit` | Submit CSR to CA (ACME), poll, return issued cert |
| GET | `/api/v1/csr/{id}` | Retrieve a stored CSR |

### Example CSR request DTO
```json
{
  "keyAlgorithm": "RSA",        // RSA | EC | ED25519
  "keySize": 2048,              // or curve "P-256" for EC
  "subject": {
    "commonName": "example.com",
    "organization": "Example Inc",
    "organizationalUnit": "IT",
    "locality": "San Francisco",
    "state": "CA",
    "country": "US"
  },
  "subjectAltNames": [
    { "type": "DNS", "value": "example.com" },
    { "type": "DNS", "value": "www.example.com" }
  ],
  "signatureAlgorithm": "SHA256withRSA"
}
```

---

## 6. CSR generation — core code sketch (Bouncy Castle)

```java
// register provider once at startup
Security.addProvider(new BouncyCastleProvider());

// 1. key pair
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
kpg.initialize(2048);
KeyPair keyPair = kpg.generateKeyPair();

// 2. subject DN
X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
    .addRDN(BCStyle.CN, "example.com")
    .addRDN(BCStyle.O,  "Example Inc")
    .addRDN(BCStyle.C,  "US")
    .build();

// 3. CSR builder
JcaPKCS10CertificationRequestBuilder csrBuilder =
    new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

// 4. SAN extension
GeneralNames sans = new GeneralNames(new GeneralName[]{
    new GeneralName(GeneralName.dNSName, "example.com"),
    new GeneralName(GeneralName.dNSName, "www.example.com")
});
ExtensionsGenerator extGen = new ExtensionsGenerator();
extGen.addExtension(Extension.subjectAlternativeName, false, sans);
csrBuilder.addAttribute(
    PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

// 5. sign
ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
    .setProvider("BC")
    .build(keyPair.getPrivate());
PKCS10CertificationRequest csr = csrBuilder.build(signer);

// 6. encode to PEM
StringWriter sw = new StringWriter();
try (JcaPEMWriter pem = new JcaPEMWriter(sw)) {
    pem.writeObject(csr);
}
String csrPem = sw.toString();   // -----BEGIN CERTIFICATE REQUEST-----
```

---

## 7. Security requirements (non-negotiable)

- **Never store private keys in plaintext.** Use KMS/HSM, or at minimum AES-GCM encryption with a key from a secrets manager.
- **Generate keys server-side only when necessary.** Client-side keygen + CSR upload is more secure (private key never touches server).
- Enforce minimum strength: RSA ≥ 2048 (prefer 3072/4096), EC ≥ P-256.
- Reject weak signature algos (no SHA-1, no MD5).
- TLS on all endpoints. AuthN + authZ on every route.
- Audit log every key generation, CSR creation, and cert operation (who, what, when).
- Rate-limit key/CSR generation endpoints.
- Validate + sanitize all DN / SAN input (prevent injection into DN strings).
- Set key generation entropy expectations; use `SecureRandom` (default, not seeded).

---

## 8. Build order (suggested milestones)

1. Spring Boot skeleton + Bouncy Castle provider config.
2. `KeyPairService` + `CsrService` — generate key + CSR, return PEM. (Core value.)
3. `CsrService.parse()` + `ValidationService` — decode & validate uploaded CSRs.
4. `ConversionService` — PEM/DER/PKCS#12.
5. Persistence + audit log.
6. Security (auth, TLS, rate limiting).
7. KMS/HSM key storage abstraction.
8. Self-signed cert issuance.
9. (Optional) ACME / DigiCert CA submission.

---

## 9. Key references

- Bouncy Castle: https://www.bouncycastle.org/documentation.html
- RFC 2986 — PKCS#10 (CSR format)
- RFC 5280 — X.509 v3 certificates
- RFC 8555 — ACME protocol
- acme4j: https://acme4j.shredzone.org/
- EJBCA (architecture reference): https://www.ejbca.org/
- DigiCert CertCentral API: https://dev.digicert.com/
- PKCS#11 / SunPKCS11 (HSM): Oracle JDK PKCS#11 reference guide
```