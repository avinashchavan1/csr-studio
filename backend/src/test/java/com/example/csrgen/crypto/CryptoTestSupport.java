package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.CsrRequest;
import com.example.csrgen.api.dto.SanEntryDto;
import com.example.csrgen.api.dto.SubjectDto;
import com.example.csrgen.domain.KeyAlgorithm;
import com.example.csrgen.domain.SanType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.List;

/**
 * Shared helpers + Bouncy Castle registration for crypto unit tests.
 */
final class CryptoTestSupport {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CryptoTestSupport() {
    }

    static ValidationService validation() {
        return new ValidationService();
    }

    static CsrService csrService() {
        return new CsrService(new KeyPairService(), validation());
    }

    static SubjectDto subject(String cn) {
        return new SubjectDto(cn, "Example Inc", "IT", "San Francisco", "California", "US", null);
    }

    static CsrRequest rsaRequest(String cn) {
        return new CsrRequest(KeyAlgorithm.RSA, 2048, null, subject(cn),
                List.of(new SanEntryDto(SanType.DNS, cn),
                        new SanEntryDto(SanType.DNS, "www." + cn)),
                null);
    }

    static CsrRequest ecRequest(String cn, String curve) {
        return new CsrRequest(KeyAlgorithm.EC, null, curve, subject(cn),
                List.of(new SanEntryDto(SanType.DNS, cn)), null);
    }
}
