package com.example.csrgen.contract;

import com.example.csrgen.persistence.CsrRecord;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Retrieves a generated CSR snapshot by its UUID (the {@code /r/<id>} permalink).
 * Returns the CSR + metadata only — never a private key.
 */
@RestController
@RequestMapping(value = "/csr/record", produces = MediaType.APPLICATION_JSON_VALUE)
public class RecordController {

    private final RecordService records;

    public RecordController(RecordService records) {
        this.records = records;
    }

    public record RecordView(String id, String csr, String keyLabel, long createdAt) {
    }

    @GetMapping("/{id}")
    public RecordView get(@PathVariable String id) {
        CsrRecord r = records.get(id).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "No saved CSR was found for this link. It may have expired or the id is wrong."));
        return new RecordView(r.getId(), r.getCsrPem(), r.getKeyLabel(), r.getCreatedAt().toEpochMilli());
    }
}
