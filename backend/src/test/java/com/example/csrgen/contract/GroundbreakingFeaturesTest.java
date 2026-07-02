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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** H1 hybrid CSR · H2 quantum scan · H3 share links. */
@SpringBootTest
@AutoConfigureMockMvc
class GroundbreakingFeaturesTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    private static final String GEN = """
            { "subject": { "commonName": "hy.example.com", "country": "US" },
              "subjectAltNames": [ { "type": "DNS", "value": "hy.example.com" } ],
              "key": { "algorithm": "RSA", "size": 2048, "format": "PKCS#8" },
              "signatureHash": "SHA-256" }""";

    /* ---------------- H1: hybrid ---------------- */

    @Test
    void hybridReturnsClassicalAndPqcPair() throws Exception {
        MvcResult r = mvc.perform(post("/csr/hybrid?pqc=ML-DSA-65")
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.classical.details.keyLabel").value("RSA 2048"))
                .andExpect(jsonPath("$.pqc.details.keyLabel").value("ML-DSA-65"))
                .andReturn();
        JsonNode n = json.readTree(r.getResponse().getContentAsString());
        assertThat(n.get("classical").get("csr").asText()).contains("BEGIN CERTIFICATE REQUEST");
        assertThat(n.get("pqc").get("csr").asText()).contains("BEGIN CERTIFICATE REQUEST");
        // same identity in both halves
        String dec1 = decodeCn(n.get("classical").get("csr").asText());
        String dec2 = decodeCn(n.get("pqc").get("csr").asText());
        assertThat(dec1).isEqualTo("hy.example.com").isEqualTo(dec2);
    }

    private String decodeCn(String csr) throws Exception {
        MvcResult d = mvc.perform(post("/csr/decode").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("csr", csr))))
                .andExpect(status().isOk()).andReturn();
        return json.readTree(d.getResponse().getContentAsString()).get("subject").get("commonName").asText();
    }

    @Test
    void hybridRejectsPqcClassicalHalf() throws Exception {
        String body = GEN.replace("\"RSA\"", "\"ML-DSA-65\"").replace("\"size\": 2048,", "");
        mvc.perform(post("/csr/hybrid").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void hybridRejectsUnknownPqcParam() throws Exception {
        mvc.perform(post("/csr/hybrid?pqc=ML-DSA-99").contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.containsString("Unknown PQC")));
    }

    /* ---------------- H2: quantum scan ---------------- */

    @Test
    void scanRsaCsrGradedVulnerable() throws Exception {
        MvcResult g = mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isOk()).andReturn();
        String csr = json.readTree(g.getResponse().getContentAsString()).get("csr").asText();
        mvc.perform(post("/csr/quantum-scan").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("csr", csr))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.quantumVulnerable").value(true))
                .andExpect(jsonPath("$.grade").value("D"))
                .andExpect(jsonPath("$.hndlRisk").value("medium"))
                .andExpect(jsonPath("$.recommendation").value(org.hamcrest.Matchers.containsString("ML-DSA")));
    }

    @Test
    void scanPqcCsrGradedSafe() throws Exception {
        String body = GEN.replace("\"RSA\", \"size\": 2048", "\"ML-DSA-65\"");
        MvcResult g = mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andReturn();
        String csr = json.readTree(g.getResponse().getContentAsString()).get("csr").asText();
        mvc.perform(post("/csr/quantum-scan").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("csr", csr))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.quantumVulnerable").value(false))
                .andExpect(jsonPath("$.grade").value("A+"))
                .andExpect(jsonPath("$.hndlRisk").value("none"));
    }

    @Test
    void scanRequiresExactlyOneInput() throws Exception {
        mvc.perform(post("/csr/quantum-scan").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/csr/quantum-scan").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"csr\":\"x\",\"host\":\"a.com\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void scanRejectsBadHostname() throws Exception {
        mvc.perform(post("/csr/quantum-scan").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"host\":\"not a host!!\"}"))
                .andExpect(status().isBadRequest());
    }

    /* ---------------- H3: share links ---------------- */

    @Test
    void shareRoundTrip() throws Exception {
        MvcResult g = mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isOk()).andReturn();
        String csr = json.readTree(g.getResponse().getContentAsString()).get("csr").asText();

        MvcResult s = mvc.perform(post("/csr/share").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("csr", csr))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andReturn();
        String id = json.readTree(s.getResponse().getContentAsString()).get("id").asText();
        assertThat(id).hasSize(10);

        mvc.perform(get("/csr/share/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.csr").value(csr));
    }

    @Test
    void shareRejectsGarbageAndPrivateKeys() throws Exception {
        mvc.perform(post("/csr/share").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"csr\":\"not a csr\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/csr/share").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"csr\":\"-----BEGIN PRIVATE KEY-----oops\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.containsString("private key")));
    }

    @Test
    void unknownShareIs400() throws Exception {
        mvc.perform(get("/csr/share/zzzzzzzzzz"))
                .andExpect(status().isBadRequest());
    }
}
