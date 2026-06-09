package com.example.csrgen.crypto;

import com.example.csrgen.domain.KeyAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * Generates key pairs using the Bouncy Castle provider.
 */
@Service
public class KeyPairService {

    private static final int DEFAULT_RSA_SIZE = 2048;
    private static final String DEFAULT_EC_CURVE = "P-256";

    public KeyPair generate(KeyAlgorithm algorithm, Integer rsaKeySize, String ecCurve) {
        try {
            return switch (algorithm) {
                case RSA -> generateRsa(rsaKeySize != null ? rsaKeySize : DEFAULT_RSA_SIZE);
                case EC -> generateEc(ecCurve != null ? ecCurve : DEFAULT_EC_CURVE);
                case ED25519 -> generateEd25519();
            };
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | InvalidParameterSpecException e) {
            throw new CryptoException("Key generation failed: " + e.getMessage(), e);
        }
    }

    private KeyPair generateRsa(int size) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    private KeyPair generateEc(String curve)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        try {
            kpg.initialize(new ECGenParameterSpec(curve));
        } catch (java.security.InvalidAlgorithmParameterException e) {
            throw new InvalidParameterSpecException("Unknown EC curve: " + curve);
        }
        return kpg.generateKeyPair();
    }

    private KeyPair generateEd25519() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        return kpg.generateKeyPair();
    }
}
