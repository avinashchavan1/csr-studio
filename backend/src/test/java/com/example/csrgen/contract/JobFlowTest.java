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
import static org.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "app.async.phase-delay-ms=0")
@AutoConfigureMockMvc
class JobFlowTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper json;

    private static final String GEN = """
            { "subject": { "commonName": "async.example.com", "country": "US" },
              "key": { "algorithm": "RSA", "size": 2048, "format": "PKCS#8" },
              "signatureHash": "SHA-256" }""";

    @Test
    void asyncReturns202ThenJobCompletes() throws Exception {
        MvcResult accepted = mvc.perform(post("/csr/generate?async=true")
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.jobId").exists())
                .andExpect(jsonPath("$.statusUrl").exists())
                .andExpect(jsonPath("$.status").value("queued"))
                .andReturn();

        String jobId = json.readTree(accepted.getResponse().getContentAsString()).get("jobId").asText();

        await().atMost(10, SECONDS).untilAsserted(() -> {
            MvcResult poll = mvc.perform(get("/csr/jobs/" + jobId))
                    .andExpect(status().isOk()).andReturn();
            JsonNode node = json.readTree(poll.getResponse().getContentAsString());
            assertThat(node.get("status").asText()).isEqualTo("done");
            assertThat(node.get("result").get("csr").asText()).contains("BEGIN CERTIFICATE REQUEST");
            assertThat(node.get("result").get("privateKey").asText()).contains("BEGIN PRIVATE KEY");
        });
    }

    @Test
    void unknownJobReturns404() throws Exception {
        mvc.perform(get("/csr/jobs/job_doesnotexist"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.message").exists());
    }

    @Test
    void idempotentSyncReturnsSameKeyPair() throws Exception {
        String key = "test-idem-key-123";
        MvcResult first = mvc.perform(post("/csr/generate")
                        .header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isOk()).andReturn();
        MvcResult second = mvc.perform(post("/csr/generate")
                        .header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isOk()).andReturn();

        String csr1 = json.readTree(first.getResponse().getContentAsString()).get("csr").asText();
        String csr2 = json.readTree(second.getResponse().getContentAsString()).get("csr").asText();
        assertThat(csr1).isEqualTo(csr2);
    }

    @Test
    void differentKeysProduceDifferentCsrs() throws Exception {
        MvcResult a = mvc.perform(post("/csr/generate").header("Idempotency-Key", "k-a")
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isOk()).andReturn();
        MvcResult b = mvc.perform(post("/csr/generate").header("Idempotency-Key", "k-b")
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isOk()).andReturn();
        String csrA = json.readTree(a.getResponse().getContentAsString()).get("csr").asText();
        String csrB = json.readTree(b.getResponse().getContentAsString()).get("csr").asText();
        assertThat(csrA).isNotEqualTo(csrB);
    }

    @Test
    void idempotentAsyncReturnsSameJobId() throws Exception {
        String key = "async-idem-key";
        MvcResult a = mvc.perform(post("/csr/generate?async=true").header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isAccepted()).andReturn();
        MvcResult b = mvc.perform(post("/csr/generate?async=true").header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON).content(GEN))
                .andExpect(status().isAccepted()).andReturn();
        String j1 = json.readTree(a.getResponse().getContentAsString()).get("jobId").asText();
        String j2 = json.readTree(b.getResponse().getContentAsString()).get("jobId").asText();
        assertThat(j1).isEqualTo(j2);
    }
}
