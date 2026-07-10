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
    private final QuantumScanService quantumScanService;
    private final com.example.csrgen.crypto.VerifyService verifyService;
    private final com.example.csrgen.crypto.SignService signService;

    public CsrContractController(ContractService contractService, JobStore jobStore,
                                 QuantumScanService quantumScanService,
                                 com.example.csrgen.crypto.VerifyService verifyService,
                                 com.example.csrgen.crypto.SignService signService) {
        this.contractService = contractService;
        this.jobStore = jobStore;
        this.quantumScanService = quantumScanService;
        this.verifyService = verifyService;
        this.signService = signService;
    }

    /** Quantum-readiness (HNDL) report for a CSR, certificate, or live host. */
    @PostMapping(value = "/quantum-scan", consumes = MediaType.APPLICATION_JSON_VALUE)
    public com.example.csrgen.contract.dto.QuantumScanResponse quantumScan(
            @RequestBody com.example.csrgen.contract.dto.QuantumScanRequest request) {
        return quantumScanService.scan(request);
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

    /** Hybrid: classical CSR (from the body's key spec) + a PQC CSR for the same identity. */
    @PostMapping(value = "/hybrid", consumes = MediaType.APPLICATION_JSON_VALUE)
    public com.example.csrgen.contract.dto.HybridResponse hybrid(
            @Valid @RequestBody GenerateRequest request,
            @RequestParam(name = "pqc", defaultValue = "ML-DSA-65") String pqc) {
        return contractService.hybrid(request, pqc);
    }

    @PostMapping(value = "/self-signed", consumes = MediaType.APPLICATION_JSON_VALUE)
    public com.example.csrgen.contract.dto.SelfSignedResponse selfSigned(
            @Valid @RequestBody GenerateRequest request,
            @RequestParam(name = "days", defaultValue = "365") int days) {
        return contractService.selfSigned(request, days);
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

    /** Verify a digital signature (detached or certificate-by-issuer). Public-key only. */
    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public com.example.csrgen.contract.dto.VerifyResponse verify(
            @RequestBody com.example.csrgen.contract.dto.VerifyRequest request) {
        return verifyService.verify(request);
    }

    /** Sign a message with a private key (used transiently, never stored). */
    @PostMapping(value = "/sign", consumes = MediaType.APPLICATION_JSON_VALUE)
    public com.example.csrgen.contract.dto.SignResponse sign(
            @RequestBody com.example.csrgen.contract.dto.SignRequest request) {
        return signService.sign(request);
    }
}
