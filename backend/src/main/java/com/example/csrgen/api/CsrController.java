package com.example.csrgen.api;

import com.example.csrgen.api.dto.CsrParseResponse;
import com.example.csrgen.api.dto.CsrRequest;
import com.example.csrgen.api.dto.CsrResponse;
import com.example.csrgen.api.dto.PemRequest;
import com.example.csrgen.api.dto.ValidationResult;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.crypto.CsrService;
import com.example.csrgen.crypto.ValidationService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/v1/csr", produces = MediaType.APPLICATION_JSON_VALUE)
public class CsrController {

    private final CsrService csrService;
    private final CsrParser csrParser;
    private final ValidationService validationService;

    public CsrController(CsrService csrService, CsrParser csrParser,
                         ValidationService validationService) {
        this.csrService = csrService;
        this.csrParser = csrParser;
        this.validationService = validationService;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public CsrResponse generate(@Valid @RequestBody CsrRequest request) {
        return csrService.generate(request);
    }

    @PostMapping(value = "/parse", consumes = MediaType.APPLICATION_JSON_VALUE)
    public CsrParseResponse parse(@Valid @RequestBody PemRequest request) {
        return csrParser.parse(request.pem());
    }

    @PostMapping(value = "/validate", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ValidationResult validate(@Valid @RequestBody PemRequest request) {
        return validationService.validateParsed(csrParser.parse(request.pem()));
    }
}
