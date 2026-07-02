package com.example.csrgen.contract;

import com.example.csrgen.crypto.CryptoException;
import com.example.csrgen.crypto.CsrParser;
import com.example.csrgen.persistence.CsrShare;
import com.example.csrgen.persistence.CsrShareRepository;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.time.Instant;

/**
 * Shareable read-only CSR review links. The CSR (never a private key) is stored under a
 * short random id; anyone with the link can view the decoded request for approval.
 */
@RestController
@RequestMapping(value = "/csr/share", produces = MediaType.APPLICATION_JSON_VALUE)
public class ShareController {

    private static final int MAX_ROWS = 500;
    private static final String ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RND = new SecureRandom();

    private final CsrShareRepository repo;
    private final CsrParser csrParser;

    public ShareController(CsrShareRepository repo, CsrParser csrParser) {
        this.repo = repo;
        this.csrParser = csrParser;
    }

    public record ShareRequest(@NotBlank String csr) {
    }

    public record ShareResponse(String id, String path, long createdAt) {
    }

    public record ShareView(String csr, long createdAt) {
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ShareResponse create(@RequestBody @jakarta.validation.Valid ShareRequest req) {
        // must be a real, parseable CSR (also blocks private-key paste-by-mistake)
        if (req.csr().contains("PRIVATE KEY")) {
            throw new CryptoException("That looks like a private key — never share private keys.");
        }
        csrParser.parse(req.csr());   // throws on garbage
        String id = randomId(10);
        CsrShare saved = repo.save(new CsrShare(id, req.csr(), Instant.now()));
        trim();
        return new ShareResponse(saved.getId(), "/csr/share/" + saved.getId(),
                saved.getCreatedAt().toEpochMilli());
    }

    @GetMapping("/{id}")
    public ShareView get(@PathVariable String id) {
        CsrShare s = repo.findById(id)
                .orElseThrow(() -> new CryptoException("Unknown or expired share link."));
        return new ShareView(s.getCsrPem(), s.getCreatedAt().toEpochMilli());
    }

    private void trim() {
        long count = repo.count();
        if (count > MAX_ROWS) {
            repo.deleteAll(repo.findByOrderByCreatedAtAsc(PageRequest.of(0, (int) (count - MAX_ROWS))));
        }
    }

    private String randomId(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(ALPHABET.charAt(RND.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }
}
