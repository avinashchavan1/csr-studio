package com.example.csrgen.contract;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** QA-CP3: security headers, no-store, guarded clear. */
@SpringBootTest
@AutoConfigureMockMvc
class HardeningTest {

    @Autowired MockMvc mvc;

    @Test
    void securityHeadersAndNoStorePresent() throws Exception {
        mvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Strict-Transport-Security", org.hamcrest.Matchers.containsString("max-age")))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void bulkClearRequiresConfirmHeader() throws Exception {
        mvc.perform(delete("/csr/history"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.message").value(org.hamcrest.Matchers.containsString("X-Confirm-Clear")));
        mvc.perform(delete("/csr/history").header("X-Confirm-Clear", "yes"))
                .andExpect(status().isNoContent());
    }
}
