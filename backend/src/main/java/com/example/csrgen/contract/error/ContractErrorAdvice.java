package com.example.csrgen.contract.error;

import com.example.csrgen.crypto.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Error handling for the contract endpoints, producing the body the UI expects:
 * {@code { "error": { "message": "...", "fields": { "commonName": "..." } } }}.
 *
 * <p>Field keys are normalised to the contract names (e.g. {@code subject.commonName}
 * → {@code commonName}) so the frontend can map them back onto form inputs.
 */
@RestControllerAdvice(basePackages = "com.example.csrgen.contract")
public class ContractErrorAdvice {

    private static final Logger log = LoggerFactory.getLogger(ContractErrorAdvice.class);

    public record ErrorBody(ErrorDetail error) {
        public record ErrorDetail(String message, Map<String, String> fields) {
        }

        static ErrorBody of(String message, Map<String, String> fields) {
            return new ErrorBody(new ErrorDetail(message, fields == null || fields.isEmpty() ? null : fields));
        }
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorBody> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(fe ->
                fields.putIfAbsent(normalize(fe.getField()), fe.getDefaultMessage()));
        String message = fields.values().stream().findFirst().orElse("Validation failed.");
        return ResponseEntity.badRequest().body(ErrorBody.of(message, fields));
    }

    @ExceptionHandler(CryptoException.class)
    public ResponseEntity<ErrorBody> handleCrypto(CryptoException ex) {
        return ResponseEntity.badRequest().body(ErrorBody.of(ex.getMessage(), null));
    }

    /** Preserve deliberate status codes (e.g. 404 for an unknown /r/&lt;id&gt;). */
    @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
    public ResponseEntity<ErrorBody> handleStatus(org.springframework.web.server.ResponseStatusException ex) {
        String message = ex.getReason() != null ? ex.getReason() : "Request failed.";
        return ResponseEntity.status(ex.getStatusCode()).body(ErrorBody.of(message, null));
    }

    /** Malformed JSON, wrong types, etc. → 400 (not 500). No internals leaked. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorBody> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(ErrorBody.of("Malformed or unreadable request body.", null));
    }

    /**
     * Unexpected failures → 500 with a static message. The real cause is logged
     * server-side, never returned to the client (no information disclosure).
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorBody> handleGeneric(Exception ex) {
        log.error("Unhandled error on contract endpoint", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorBody.of("An internal error occurred. Please try again.", null));
    }

    /** "subject.commonName" → "commonName"; leaves already-flat names untouched. */
    private String normalize(String field) {
        int dot = field.lastIndexOf('.');
        return dot >= 0 ? field.substring(dot + 1) : field;
    }
}
