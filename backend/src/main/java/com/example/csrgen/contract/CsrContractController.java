package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.AsyncAccepted;
import com.example.csrgen.contract.dto.DecodeRequest;
import com.example.csrgen.contract.dto.DecodeResponse;
import com.example.csrgen.contract.dto.GenerateRequest;
import com.example.csrgen.contract.dto.GenerateResponse;
import com.example.csrgen.contract.dto.JobStatusResponse;
import com.example.csrgen.contract.dto.MatchRequest;
import com.example.csrgen.contract.dto.MatchResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Implements the CSR Studio API contract consumed by the React frontend.
 */
@RestController
@RequestMapping(value = "/csr", produces = MediaType.APPLICATION_JSON_VALUE)
public class CsrContractController {

    private final ContractService contractService;
    private final JobStore jobStore;

    public CsrContractController(ContractService contractService, JobStore jobStore) {
        this.contractService = contractService;
        this.jobStore = jobStore;
    }

    /**
     * Generate a CSR. Synchronous (200) by default; when {@code ?async=true} the work is
     * queued and a 202 + jobId is returned for the client to poll. An optional
     * {@code Idempotency-Key} header dedupes retries.
     */
    @PostMapping(value = "/generate", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> generate(
            @Valid @RequestBody GenerateRequest request,
            @RequestParam(name = "async", defaultValue = "false") boolean async,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey) {
        if (async) {
            JobState job = jobStore.submitAsync(request, idempotencyKey);
            AsyncAccepted body = new AsyncAccepted(
                    job.getId(), "/csr/jobs/" + job.getId(), job.getStatus());
            return ResponseEntity.accepted().body(body);
        }
        return ResponseEntity.ok(jobStore.generateSync(request, idempotencyKey));
    }

    @GetMapping("/jobs/{jobId}")
    public ResponseEntity<JobStatusResponse> job(@PathVariable String jobId) {
        JobState job = jobStore.get(jobId);
        if (job == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new JobStatusResponse(
                    "error", null, null, null, new JobStatusResponse.Error("Unknown job " + jobId)));
        }
        JobStatusResponse.Error error = job.getError() == null
                ? null : new JobStatusResponse.Error(job.getError());
        return ResponseEntity.ok(new JobStatusResponse(
                job.getStatus(), job.getProgress(), job.getMessage(), job.getResult(), error));
    }

    @PostMapping(value = "/decode", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DecodeResponse decode(@Valid @RequestBody DecodeRequest request) {
        return contractService.decode(request.csr());
    }

    @PostMapping(value = "/match", consumes = MediaType.APPLICATION_JSON_VALUE)
    public MatchResponse match(@Valid @RequestBody MatchRequest request) {
        return contractService.match(request.csr(), request.privateKey());
    }
}
