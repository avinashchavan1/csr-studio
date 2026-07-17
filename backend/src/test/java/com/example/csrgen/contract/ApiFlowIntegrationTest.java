package com.example.csrgen.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * True end-to-end flows through the HTTP layer (real Spring context, Bouncy Castle,
 * and H2 persistence): generate → decode → match → retrieve by /r/&lt;id&gt;, across
 * classical and post-quantum algorithms; plus self-signed → PKCS#12 and hybrid.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ApiFlowIntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    private String genBody(Map<String, Object> key) throws Exception {
        return json.writeValueAsString(Map.of(
                "subject", Map.of("commonName", "flow.example.com", "organization", "Flow Inc.", "country", "US"),
                "subjectAltNames", java.util.List.of(
                        Map.of("type", "DNS", "value", "flow.example.com"),
                        Map.of("type", "DNS", "value", "www.flow.example.com")),
                "key", key,
                "signatureHash", "SHA-256"));
    }

    private JsonNode postJson(String path, String body) throws Exception {
        MvcResult res = mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andReturn();
        return json.readTree(res.getResponse().getContentAsString());
    }

    static Stream<Arguments> algorithms() {
        return Stream.of(
                Arguments.of("RSA", Map.of("algorithm", "RSA", "size", 2048, "format", "PKCS#8")),
                Arguments.of("ECDSA", Map.of("algorithm", "ECDSA", "curve", "P-256", "format", "PKCS#8")),
                Arguments.of("Ed25519", Map.of("algorithm", "Ed25519", "format", "PKCS#8")),
                Arguments.of("ML-DSA-65", Map.of("algorithm", "ML-DSA-65", "format", "PKCS#8")));
    }

    @ParameterizedTest(name = "E2E flow: {0}")
    @MethodSource("algorithms")
    void generateDecodeMatchRetrieve(String label, Map<String, Object> key) throws Exception {
        // 1) generate
        JsonNode g = postJson("/csr/generate", genBody(key));
        String csr = g.get("csr").asText();
        String priv = g.get("privateKey").asText();
        String id = g.get("id").asText();
        assertThat(csr).contains("BEGIN CERTIFICATE REQUEST");
        assertThat(id).isNotBlank();

        // 2) decode → self-signature valid, subject + SANs survive
        String decodeBody = json.writeValueAsString(Map.of("csr", csr));
        mvc.perform(post("/csr/decode").contentType(MediaType.APPLICATION_JSON).content(decodeBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject.commonName").value("flow.example.com"))
                .andExpect(jsonPath("$.signature.valid").value(true))
                .andExpect(jsonPath("$.subjectAltNames.length()").value(2));

        // 3) match → private key corresponds to CSR (server-side match is RSA-only;
        //    for other key types it reports supported=false rather than a mismatch).
        String matchBody = json.writeValueAsString(Map.of("csr", csr, "privateKey", priv));
        JsonNode m = postJson("/csr/match", matchBody);
        if (label.equals("RSA")) {
            assertThat(m.get("match").asBoolean()).isTrue();
        } else {
            assertThat(m.get("supported").asBoolean()).isFalse();
        }

        // 4) retrieve by /r/<id> → CSR matches, no private key stored
        MvcResult rec = mvc.perform(get("/csr/record/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.csr").value(csr))
                .andReturn();
        assertThat(rec.getResponse().getContentAsString()).doesNotContain("PRIVATE KEY");
    }

    @Test
    void selfSignedThenPkcs12() throws Exception {
        // self-sign an RSA cert, then bundle it as PKCS#12
        String body = genBody(Map.of("algorithm", "RSA", "size", 2048, "format", "PKCS#8"));
        JsonNode s = postJson("/csr/self-signed?days=90", body);
        String cert = s.get("certificate").asText();
        String key = s.get("privateKey").asText();
        assertThat(cert).contains("BEGIN CERTIFICATE");

        String p12Body = json.writeValueAsString(Map.of(
                "certificatePem", cert, "privateKeyPem", key, "password", "changeit", "alias", "1"));
        mvc.perform(post("/v1/convert/pkcs12").contentType(MediaType.APPLICATION_JSON).content(p12Body))
                .andExpect(status().isOk());
    }

    @Test
    void verifyEndpointE2E() throws Exception {
        // sign a message with a fresh EC key, then verify it over HTTP
        var kp = new com.example.csrgen.crypto.KeyPairService()
                .generate(com.example.csrgen.domain.KeyAlgorithm.EC, null, "P-256");
        var sig = java.security.Signature.getInstance("SHA256withECDSA",
                org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
        sig.initSign(kp.getPrivate());
        byte[] msg = "e2e-verify".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        sig.update(msg);
        String sigB64 = java.util.Base64.getEncoder().encodeToString(sig.sign());
        String pub = com.example.csrgen.crypto.PemUtil.toPem(kp.getPublic());

        String body = json.writeValueAsString(Map.of(
                "mode", "detached", "message", "e2e-verify", "messageEncoding", "utf8",
                "signature", sigB64, "signatureEncoding", "base64",
                "publicKey", pub, "algorithm", "auto", "hash", "SHA-256"));
        mvc.perform(post("/csr/verify").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.keyKind").value("EC"));

        // tampered message → invalid, with a reason
        String bad = json.writeValueAsString(Map.of(
                "mode", "detached", "message", "TAMPERED", "messageEncoding", "utf8",
                "signature", sigB64, "signatureEncoding", "base64",
                "publicKey", pub, "algorithm", "auto"));
        mvc.perform(post("/csr/verify").contentType(MediaType.APPLICATION_JSON).content(bad))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").isNotEmpty());
    }

    @Test
    void signThenVerifyOverHttp() throws Exception {
        // sign server-side, then verify the returned signature + derived public key
        var kp = new com.example.csrgen.crypto.KeyPairService()
                .generate(com.example.csrgen.domain.KeyAlgorithm.ML_DSA, null, "ML-DSA-65");
        String privPem = com.example.csrgen.crypto.PemUtil.toPem(kp.getPrivate());

        String signBody = json.writeValueAsString(Map.of(
                "message", "http-sign-loop", "messageEncoding", "utf8",
                "privateKey", privPem, "algorithm", "auto"));
        JsonNode s = postJson("/csr/sign", signBody);
        assertThat(s.get("signature").asText()).isNotBlank();
        assertThat(s.get("keyKind").asText()).isEqualTo("ML-DSA");
        assertThat(s.get("pqc").asBoolean()).isTrue();
        String sig = s.get("signature").asText();
        String pub = s.get("publicKey").asText();
        assertThat(pub).contains("PUBLIC KEY");

        String verifyBody = json.writeValueAsString(Map.of(
                "mode", "detached", "message", "http-sign-loop", "messageEncoding", "utf8",
                "signature", sig, "signatureEncoding", "base64",
                "publicKey", pub, "algorithm", "auto"));
        mvc.perform(post("/csr/verify").contentType(MediaType.APPLICATION_JSON).content(verifyBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.pqc").value(true));
    }

    @Test
    void hybridClassicalPlusPqc() throws Exception {
        String body = genBody(Map.of("algorithm", "RSA", "size", 2048, "format", "PKCS#8"));
        mvc.perform(post("/csr/hybrid?pqc=ML-DSA-65").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.classical.csr").value(org.hamcrest.Matchers.containsString("CERTIFICATE REQUEST")))
                .andExpect(jsonPath("$.pqc.csr").value(org.hamcrest.Matchers.containsString("CERTIFICATE REQUEST")));
    }

    @Test
    void convertKeyOverHttp() throws Exception {
        // generate an EC CSR, feed its private key through the converter,
        // then feed the returned public key back in — fingerprints must agree
        String body = genBody(Map.of("algorithm", "ECDSA", "curve", "P-256", "format", "PKCS#8"));
        JsonNode g = postJson("/csr/generate", body);
        String keyPem = g.get("privateKey").asText();

        JsonNode c = postJson("/csr/convert-key", json.writeValueAsString(Map.of("input", keyPem)));
        assertThat(c.get("inputType").asText()).isEqualTo("private-key");
        assertThat(c.get("keyKind").asText()).isEqualTo("EC");
        assertThat(c.get("keyDetail").asText()).isEqualTo("P-256");
        assertThat(c.get("pkcs8Pem").asText()).contains("BEGIN PRIVATE KEY");
        assertThat(c.get("traditionalPem").asText()).contains("BEGIN EC PRIVATE KEY");
        assertThat(c.get("jwk").get("crv").asText()).isEqualTo("P-256");
        assertThat(c.get("sshPublicKey").asText()).startsWith("ecdsa-sha2-nistp256 ");

        JsonNode p = postJson("/csr/convert-key",
                json.writeValueAsString(Map.of("input", c.get("publicPem").asText())));
        assertThat(p.get("inputType").asText()).isEqualTo("public-key");
        assertThat(p.get("spkiSha256").asText()).isEqualTo(c.get("spkiSha256").asText());
    }

    @Test
    void chainOverHttp() throws Exception {
        // self-sign a cert, then run it through the chain analyser
        String body = genBody(Map.of("algorithm", "RSA", "size", 2048, "format", "PKCS#8"));
        JsonNode s = postJson("/csr/self-signed?days=90", body);
        String cert = s.get("certificate").asText();

        JsonNode r = postJson("/csr/chain", json.writeValueAsString(Map.of("certificates", cert)));
        assertThat(r.get("complete").asBoolean()).isTrue();
        assertThat(r.get("chain")).hasSize(1);
        assertThat(r.get("chain").get(0).get("selfSigned").asBoolean()).isTrue();
        assertThat(r.get("chain").get(0).get("keyKind").asText()).isEqualTo("RSA");
        assertThat(r.get("orderedPem").asText()).contains("BEGIN CERTIFICATE");

        // pasting a private key must be refused with a friendly error
        String keyPem = s.get("privateKey").asText();
        mvc.perform(post("/csr/chain").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("certificates", keyPem))))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.error.message").value(
                        org.hamcrest.Matchers.containsString("never paste private keys")));
    }
}
