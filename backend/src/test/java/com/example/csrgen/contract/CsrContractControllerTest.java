package com.example.csrgen.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CsrContractControllerTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper json;

    private static final String GEN_RSA = """
            { "subject": { "commonName": "shop.example.com", "organization": "Example Inc.", "country": "US" },
              "subjectAltNames": [ { "type": "DNS", "value": "shop.example.com" }, { "type": "IP", "value": "203.0.113.10" } ],
              "key": { "algorithm": "RSA", "size": 2048, "format": "PKCS#8" },
              "signatureHash": "SHA-256" }""";

    @Test
    void healthOk() throws Exception {
        mvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"));
    }

    @Test
    void generateReturnsContractShape() throws Exception {
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON).content(GEN_RSA))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.csr").value(org.hamcrest.Matchers.containsString("BEGIN CERTIFICATE REQUEST")))
                .andExpect(jsonPath("$.privateKey").value(org.hamcrest.Matchers.containsString("BEGIN PRIVATE KEY")))
                .andExpect(jsonPath("$.details.keyLabel").value("RSA 2048"))
                .andExpect(jsonPath("$.details.keyFormat").value("PKCS#8"));
    }

    @Test
    void noCommonNameAndNoSanRejected() throws Exception {
        // CN is now optional (SAN-only CSRs allowed) — but a request with neither is rejected.
        String body = """
                { "subject": { "organization": "X" },
                  "key": { "algorithm": "RSA", "size": 2048, "format": "PKCS#8" },
                  "signatureHash": "SHA-256" }""";
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(
                        org.hamcrest.Matchers.containsString("Common Name or at least one Subject Alternative Name")));
    }

    @Test
    void weakRsaKeyRejected() throws Exception {
        String body = """
                { "subject": { "commonName": "a.com" },
                  "key": { "algorithm": "RSA", "size": 1024, "format": "PKCS#8" },
                  "signatureHash": "SHA-256" }""";
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.containsString("2048")));
    }

    @Test
    void decodeReturnsSubjectAndSignature() throws Exception {
        MvcResult gen = mvc.perform(post("/csr/generate")
                        .contentType(MediaType.APPLICATION_JSON).content(GEN_RSA))
                .andExpect(status().isOk()).andReturn();
        JsonNode genJson = json.readTree(gen.getResponse().getContentAsString());
        String csr = genJson.get("csr").asText();

        String decodeBody = json.writeValueAsString(java.util.Map.of("csr", csr));
        mvc.perform(post("/csr/decode").contentType(MediaType.APPLICATION_JSON).content(decodeBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject.commonName").value("shop.example.com"))
                .andExpect(jsonPath("$.key.kind").value("RSA"))
                .andExpect(jsonPath("$.key.bits").value(2048))
                .andExpect(jsonPath("$.signature.valid").value(true));
    }

    @Test
    void matchReturnsTrueForGeneratedPair() throws Exception {
        MvcResult gen = mvc.perform(post("/csr/generate")
                        .contentType(MediaType.APPLICATION_JSON).content(GEN_RSA))
                .andExpect(status().isOk()).andReturn();
        JsonNode g = json.readTree(gen.getResponse().getContentAsString());

        String matchBody = json.writeValueAsString(java.util.Map.of(
                "csr", g.get("csr").asText(), "privateKey", g.get("privateKey").asText()));
        mvc.perform(post("/csr/match").contentType(MediaType.APPLICATION_JSON).content(matchBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.supported").value(true))
                .andExpect(jsonPath("$.match").value(true))
                .andExpect(jsonPath("$.bits").value(2048));
    }

    @Test
    void decodeInvalidPemReturnsError() throws Exception {
        String body = json.writeValueAsString(java.util.Map.of("csr", "garbage"));
        mvc.perform(post("/csr/decode").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").exists());
        assertThat(true).isTrue();
    }
}
