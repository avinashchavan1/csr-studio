package com.example.csrgen.contract.error;

import com.example.csrgen.crypto.CryptoException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorBody> handleGeneric(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorBody.of("Internal error: " + ex.getMessage(), null));
    }

    /** "subject.commonName" → "commonName"; leaves already-flat names untouched. */
    private String normalize(String field) {
        int dot = field.lastIndexOf('.');
        return dot >= 0 ? field.substring(dot + 1) : field;
    }
}
