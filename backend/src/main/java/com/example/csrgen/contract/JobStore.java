package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.GenerateRequest;
import com.example.csrgen.contract.dto.GenerateResponse;
import com.example.csrgen.crypto.CryptoException;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * In-memory async job store + idempotency cache for CSR generation.
 *
 * <p>Async jobs move through queued → processing (generating key, signing) → done|error.
 * An {@code Idempotency-Key} dedupes both sync results and async jobs so a client retry
 * never produces a second key pair.
 */
@Component
public class JobStore {

    private static final Logger log = LoggerFactory.getLogger(JobStore.class);

    private final ContractService contractService;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    private final ConcurrentHashMap<String, JobState> jobs = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, GenerateResponse> idemResults = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> idemJobs = new ConcurrentHashMap<>();

    /** Delay between simulated phases so the UI progress stepper is observable. */
    @Value("${app.async.phase-delay-ms:200}")
    private long phaseDelayMs;

    public JobStore(ContractService contractService) {
        this.contractService = contractService;
    }

    /** Synchronous generation with optional idempotent caching. */
    public GenerateResponse generateSync(GenerateRequest req, String idemKey) {
        if (idemKey != null && !idemKey.isBlank()) {
            GenerateResponse cached = idemResults.get(idemKey);
            if (cached != null) {
                return cached;
            }
            GenerateResponse fresh = contractService.generate(req);
            idemResults.putIfAbsent(idemKey, fresh);
            return idemResults.get(idemKey);
        }
        return contractService.generate(req);
    }

    /** Submits an async job (or returns the existing one for a repeated idempotency key). */
    public JobState submitAsync(GenerateRequest req, String idemKey) {
        if (idemKey != null && !idemKey.isBlank()) {
            String existingId = idemJobs.get(idemKey);
            if (existingId != null) {
                JobState existing = jobs.get(existingId);
                if (existing != null) {
                    return existing;
                }
            }
        }
        String id = "job_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        JobState job = new JobState(id);
        jobs.put(id, job);
        if (idemKey != null && !idemKey.isBlank()) {
            idemJobs.put(idemKey, id);
        }
        executor.submit(() -> run(job, req));
        return job;
    }

    public JobState get(String id) {
        return jobs.get(id);
    }

    private void run(JobState job, GenerateRequest req) {
        try {
            job.setStatus("processing");
            job.setMessage("Generating key pair");
            job.setProgress(0.35);
            sleep();

            GenerateResponse result = contractService.generate(req);

            job.setMessage("Signing request");
            job.setProgress(0.8);
            sleep();

            job.setResult(result);
            job.setProgress(1.0);
            job.setMessage(null);
            job.setStatus("done");
        } catch (CryptoException e) {
            job.setError(e.getMessage());
            job.setStatus("error");
        } catch (Exception e) {
            log.error("Async CSR job {} failed", job.getId(), e);
            job.setError("Generation failed: " + e.getMessage());
            job.setStatus("error");
        }
    }

    private void sleep() {
        if (phaseDelayMs <= 0) {
            return;
        }
        try {
            Thread.sleep(phaseDelayMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }
}
