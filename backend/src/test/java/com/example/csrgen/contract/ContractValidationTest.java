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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** QA-CP2: validation + error-handling hardening. */
@SpringBootTest
@AutoConfigureMockMvc
class ContractValidationTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    private String gen(String subject, String sans, String key) {
        return "{\"subject\":" + subject + ",\"subjectAltNames\":" + sans
                + ",\"key\":" + key + ",\"signatureHash\":\"SHA-256\"}";
    }

    private static final String RSA = "{\"algorithm\":\"RSA\",\"size\":2048,\"format\":\"PKCS#8\"}";

    @Test
    void unknownAlgorithmRejected() throws Exception {
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON)
                        .content(gen("{\"commonName\":\"a.com\"}", "[]", "{\"algorithm\":\"DSA\",\"size\":2048}")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.containsString("Unsupported key algorithm")));
    }

    @Test
    void badCountryRejectedWithField() throws Exception {
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON)
                        .content(gen("{\"commonName\":\"a.com\",\"country\":\"USA\"}", "[]", RSA)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.fields.country").exists());
    }

    @Test
    void badEmailRejectedWithField() throws Exception {
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON)
                        .content(gen("{\"commonName\":\"a.com\",\"email\":\"not-an-email\"}", "[]", RSA)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.fields.email").exists());
    }

    @Test
    void invalidIpSanReturns400Not500() throws Exception {
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON)
                        .content(gen("{\"commonName\":\"a.com\"}", "[{\"type\":\"IP\",\"value\":\"999.999.999.999\"}]", RSA)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.containsString("Invalid IP")));
    }

    @Test
    void invalidDnsSanRejected() throws Exception {
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON)
                        .content(gen("{\"commonName\":\"a.com\"}", "[{\"type\":\"DNS\",\"value\":\"has spaces .com\"}]", RSA)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.containsString("Invalid DNS")));
    }

    @Test
    void malformedJsonReturns400() throws Exception {
        mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON).content("{bad json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value("Malformed or unreadable request body."));
    }

    @Test
    void cnAutoAddedToSan() throws Exception {
        // CN not in the SAN list → backend must auto-include it (browsers ignore CN)
        MvcResult gen = mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON)
                        .content(gen("{\"commonName\":\"cn.example.com\"}",
                                "[{\"type\":\"DNS\",\"value\":\"alt.example.com\"}]", RSA)))
                .andExpect(status().isOk()).andReturn();
        String csr = json.readTree(gen.getResponse().getContentAsString()).get("csr").asText();

        MvcResult dec = mvc.perform(post("/csr/decode").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("csr", csr))))
                .andExpect(status().isOk()).andReturn();
        JsonNode sans = json.readTree(dec.getResponse().getContentAsString()).get("subjectAltNames");
        assertThat(sans.toString()).contains("cn.example.com").contains("alt.example.com");
    }

    @Test
    void cnOnlyStillProducesSan() throws Exception {
        MvcResult gen = mvc.perform(post("/csr/generate").contentType(MediaType.APPLICATION_JSON)
                        .content(gen("{\"commonName\":\"solo.example.com\"}", "[]", RSA)))
                .andExpect(status().isOk()).andReturn();
        String csr = json.readTree(gen.getResponse().getContentAsString()).get("csr").asText();
        MvcResult dec = mvc.perform(post("/csr/decode").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("csr", csr))))
                .andExpect(status().isOk()).andReturn();
        assertThat(json.readTree(dec.getResponse().getContentAsString()).get("subjectAltNames").toString())
                .contains("solo.example.com");
    }
}
