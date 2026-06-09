package com.example.csrgen.crypto;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Confirms a private key corresponds to the public key inside a CSR.
 *
 * <p>RSA is fully supported (compares modulus + public exponent). Other key
 * types report {@code supported = false}.
 */
@Service
public class MatchService {

    private final CsrParser csrParser;
    private final ConversionService conversionService;

    public MatchService(CsrParser csrParser, ConversionService conversionService) {
        this.csrParser = csrParser;
        this.conversionService = conversionService;
    }

    /** Result of a key-match check, mirroring the design's contract shape. */
    public record Result(boolean supported, boolean match, Integer bits) {
        static Result unsupported() {
            return new Result(false, false, null);
        }
    }

    public Result match(String csrPem, String keyPem) {
        PKCS10CertificationRequest csr = csrParser.decode(csrPem);
        PublicKey csrPub = csrParser.toPublicKey(csr);
        if (!(csrPub instanceof RSAPublicKey rsaPub)) {
            return Result.unsupported();
        }

        PrivateKey priv;
        try {
            priv = conversionService.readPrivateKey(keyPem);
        } catch (CryptoException e) {
            return Result.unsupported();
        }
        if (!(priv instanceof RSAPrivateCrtKey rsaPriv)) {
            return Result.unsupported();
        }

        boolean match = rsaPub.getModulus().equals(rsaPriv.getModulus())
                && rsaPub.getPublicExponent().equals(rsaPriv.getPublicExponent());
        return new Result(true, match, rsaPriv.getModulus().bitLength());
    }
}
