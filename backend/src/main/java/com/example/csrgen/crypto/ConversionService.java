package com.example.csrgen.crypto;

import com.example.csrgen.api.dto.ConvertRequest;
import com.example.csrgen.api.dto.ConvertResponse;
import com.example.csrgen.api.dto.Pkcs12Request;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Format conversions: PEM &lt;-&gt; DER and PKCS#12 (.p12/.pfx) bundling.
 */
@Service
public class ConversionService {

    public ConvertResponse convert(ConvertRequest req) {
        if (req.from() == req.to()) {
            throw new CryptoException("from and to formats are identical");
        }
        if (req.from() == ConvertRequest.Format.PEM) {
            if (!StringUtils.hasText(req.pem())) {
                throw new CryptoException("pem is required for PEM->DER");
            }
            byte[] der = PemUtil.pemToDer(req.pem());
            return new ConvertResponse(ConvertRequest.Format.DER, null, PemUtil.base64Encode(der));
        } else {
            if (!StringUtils.hasText(req.derBase64()) || !StringUtils.hasText(req.pemType())) {
                throw new CryptoException("derBase64 and pemType are required for DER->PEM");
            }
            byte[] der = PemUtil.base64Decode(req.derBase64());
            String pem = PemUtil.toPem(req.pemType(), der);
            return new ConvertResponse(ConvertRequest.Format.PEM, pem, null);
        }
    }

    /**
     * Bundles a leaf certificate + private key (+ optional CA chain) into PKCS#12 bytes.
     */
    public byte[] toPkcs12(Pkcs12Request req) {
        try {
            X509Certificate leaf = readCertificate(req.certificatePem());
            PrivateKey key = readPrivateKey(req.privateKeyPem());

            List<Certificate> chain = new ArrayList<>();
            chain.add(leaf);
            if (req.caChainPem() != null) {
                for (String caPem : req.caChainPem()) {
                    if (StringUtils.hasText(caPem)) {
                        chain.add(readCertificate(caPem));
                    }
                }
            }

            String alias = StringUtils.hasText(req.alias()) ? req.alias() : "1";
            char[] password = req.password().toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(null, null);
            ks.setKeyEntry(alias, key, password, chain.toArray(new Certificate[0]));

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, password);
            return out.toByteArray();
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("PKCS#12 bundling failed: " + e.getMessage(), e);
        }
    }

    private X509Certificate readCertificate(String pem) {
        try {
            byte[] der = PemUtil.pemToDer(pem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509",
                    BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new CryptoException("Invalid certificate PEM: " + e.getMessage(), e);
        }
    }

    /** Reads an unencrypted private key from PEM (PKCS#1 or PKCS#8). */
    public PrivateKey readPrivateKey(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter conv = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (obj instanceof PrivateKeyInfo pki) {
                return conv.getPrivateKey(pki);
            }
            if (obj instanceof PEMKeyPair kp) {
                return conv.getPrivateKey(kp.getPrivateKeyInfo());
            }
            throw new CryptoException("Unsupported private key PEM format");
        } catch (IOException e) {
            throw new CryptoException("Invalid private key PEM: " + e.getMessage(), e);
        }
    }
}
