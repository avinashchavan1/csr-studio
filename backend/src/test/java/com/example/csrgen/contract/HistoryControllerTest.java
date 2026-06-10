package com.example.csrgen.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HistoryControllerTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper json;

    private static final String REC = """
            { "commonName": "hist.example.com", "organization": "Acme",
              "keyLabel": "RSA 2048", "keyDetail": "2048-bit", "keyFormat": "PKCS#8",
              "signatureAlgorithm": "SHA-256",
              "sans": [ { "type": "DNS", "value": "hist.example.com" }, { "type": "IP", "value": "10.0.0.1" } ],
              "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\\nMIIC...\\n-----END CERTIFICATE REQUEST-----" }""";

    @BeforeEach
    void clean() throws Exception {
        mvc.perform(delete("/csr/history").header("X-Confirm-Clear", "yes")).andExpect(status().isNoContent());
    }

    @Test
    void saveThenListReturnsRecordWithIdAndCreatedAt() throws Exception {
        MvcResult saved = mvc.perform(post("/csr/history")
                        .contentType(MediaType.APPLICATION_JSON).content(REC))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.createdAt").isNumber())
                .andExpect(jsonPath("$.commonName").value("hist.example.com"))
                .andExpect(jsonPath("$.sans[1].type").value("IP"))
                .andReturn();
        String id = json.readTree(saved.getResponse().getContentAsString()).get("id").asText();

        mvc.perform(get("/csr/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(id))
                .andExpect(jsonPath("$[0].keyLabel").value("RSA 2048"));
    }

    @Test
    void neverPersistsPrivateKey() throws Exception {
        // body includes a stray privateKey field — it must be ignored, never stored or returned.
        String withKey = REC.replaceFirst("\\{", "{ \"privateKey\": \"-----BEGIN PRIVATE KEY-----secret\",");
        MvcResult saved = mvc.perform(post("/csr/history")
                        .contentType(MediaType.APPLICATION_JSON).content(withKey))
                .andExpect(status().isOk()).andReturn();
        String body = saved.getResponse().getContentAsString();
        assertThat(body).doesNotContain("PRIVATE KEY");
        assertThat(body).doesNotContain("secret");

        String listBody = mvc.perform(get("/csr/history")).andReturn().getResponse().getContentAsString();
        assertThat(listBody).doesNotContain("PRIVATE KEY");
    }

    @Test
    void deleteByIdRemovesIt() throws Exception {
        MvcResult saved = mvc.perform(post("/csr/history")
                        .contentType(MediaType.APPLICATION_JSON).content(REC))
                .andExpect(status().isOk()).andReturn();
        String id = json.readTree(saved.getResponse().getContentAsString()).get("id").asText();

        mvc.perform(delete("/csr/history/" + id)).andExpect(status().isNoContent());
        mvc.perform(get("/csr/history")).andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void clearRemovesAll() throws Exception {
        mvc.perform(post("/csr/history").contentType(MediaType.APPLICATION_JSON).content(REC));
        mvc.perform(post("/csr/history").contentType(MediaType.APPLICATION_JSON).content(REC));
        mvc.perform(delete("/csr/history").header("X-Confirm-Clear", "yes")).andExpect(status().isNoContent());
        mvc.perform(get("/csr/history")).andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void missingCsrPemRejected() throws Exception {
        String bad = "{ \"commonName\": \"x.com\" }";
        mvc.perform(post("/csr/history").contentType(MediaType.APPLICATION_JSON).content(bad))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").exists());
    }
}
