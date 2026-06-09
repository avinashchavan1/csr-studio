package com.example.csrgen.api;

import com.example.csrgen.api.dto.ConvertRequest;
import com.example.csrgen.api.dto.ConvertResponse;
import com.example.csrgen.api.dto.Pkcs12Request;
import com.example.csrgen.crypto.ConversionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/convert")
public class ConvertController {

    private final ConversionService conversionService;

    public ConvertController(ConversionService conversionService) {
        this.conversionService = conversionService;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ConvertResponse convert(@Valid @RequestBody ConvertRequest request) {
        return conversionService.convert(request);
    }

    @PostMapping(value = "/pkcs12", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> pkcs12(@Valid @RequestBody Pkcs12Request request) {
        byte[] p12 = conversionService.toPkcs12(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"bundle.p12\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(p12);
    }
}
