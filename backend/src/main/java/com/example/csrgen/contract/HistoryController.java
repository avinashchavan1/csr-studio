package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.HistoryRecord;
import com.example.csrgen.crypto.CryptoException;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Server-side CSR history (CSR + metadata only; no private keys).
 */
@RestController
@RequestMapping(value = "/csr/history", produces = MediaType.APPLICATION_JSON_VALUE)
public class HistoryController {

    private final HistoryService historyService;

    public HistoryController(HistoryService historyService) {
        this.historyService = historyService;
    }

    @GetMapping
    public List<HistoryRecord> list() {
        return historyService.list();
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public HistoryRecord save(@Valid @RequestBody HistoryRecord record) {
        return historyService.save(record);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String id) {
        historyService.delete(id);
    }

    /**
     * Bulk clear. Requires an explicit {@code X-Confirm-Clear: yes} header so a casual
     * or accidental request can't wipe the (currently shared, unauthenticated) history.
     */
    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void clear(@RequestHeader(value = "X-Confirm-Clear", required = false) String confirm) {
        if (!"yes".equalsIgnoreCase(confirm)) {
            throw new CryptoException("Clearing all history requires the X-Confirm-Clear: yes header.");
        }
        historyService.clear();
    }
}
