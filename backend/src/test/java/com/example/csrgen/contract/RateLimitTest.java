package com.example.csrgen.contract;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** QA-CP3 / M-6: rate limiting. Own context with a tiny capacity. */
@SpringBootTest(properties = "app.ratelimit.capacity=2")
@AutoConfigureMockMvc
class RateLimitTest {

    @Autowired MockMvc mvc;

    private static final String REC =
            "{\"commonName\":\"rl.example.com\",\"csrPem\":\"-----BEGIN CERTIFICATE REQUEST-----\\nx\\n-----END CERTIFICATE REQUEST-----\"}";

    @Test
    void exceedingCapacityReturns429() throws Exception {
        // capacity=2 → first two pass, third is throttled
        mvc.perform(post("/csr/history").contentType(MediaType.APPLICATION_JSON).content(REC))
                .andExpect(status().isOk());
        mvc.perform(post("/csr/history").contentType(MediaType.APPLICATION_JSON).content(REC))
                .andExpect(status().isOk());
        mvc.perform(post("/csr/history").contentType(MediaType.APPLICATION_JSON).content(REC))
                .andExpect(status().is(429));
    }
}
