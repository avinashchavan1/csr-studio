package com.example.csrgen.contract;

import com.example.csrgen.contract.dto.GenerateResponse;

/**
 * Mutable state of an async generation job. Fields are volatile because a worker
 * thread writes them while request threads read them during polling.
 */
public class JobState {

    private final String id;
    private volatile String status = "queued";
    private volatile Double progress;
    private volatile String message;
    private volatile GenerateResponse result;
    private volatile String error;

    public JobState(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Double getProgress() {
        return progress;
    }

    public void setProgress(Double progress) {
        this.progress = progress;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public GenerateResponse getResult() {
        return result;
    }

    public void setResult(GenerateResponse result) {
        this.result = result;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }
}
