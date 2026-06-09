package com.example.csrgen.config;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

/**
 * Registers the Bouncy Castle JCE provider once at startup.
 * All crypto services rely on the "BC" provider being available.
 */
@Configuration
public class CryptoConfig {

    @PostConstruct
    public void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
