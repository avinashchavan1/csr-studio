package com.example.csrgen.domain;

/**
 * Supported key pair algorithms — classical + post-quantum (PQC).
 */
public enum KeyAlgorithm {
    RSA,
    EC,
    ED25519,
    // Post-quantum (Bouncy Castle). The specific parameter set (e.g. "ML-DSA-65")
    // is carried alongside as the algorithm name used for keygen + signing.
    ML_DSA,   // FIPS 204 (CRYSTALS-Dilithium)
    SLH_DSA,  // FIPS 205 (SPHINCS+)
    FALCON    // FN-DSA (Falcon)
}
