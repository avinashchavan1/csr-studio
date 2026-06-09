package com.example.csrgen.crypto;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Base64;

/**
 * Helpers to encode crypto objects to PEM strings.
 */
public final class PemUtil {

    private PemUtil() {
    }

    /**
     * Writes any PEM-encodable object (CSR, certificate, public key) to a PEM string.
     */
    public static String toPem(Object obj) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(obj);
            writer.flush();
            return sw.toString();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode PEM", e);
        }
    }

    /**
     * Writes raw DER bytes under the given PEM type header
     * (e.g. "PRIVATE KEY", "PUBLIC KEY").
     */
    public static String toPem(String type, byte[] der) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(new PemObject(type, der));
            writer.flush();
            return sw.toString();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode PEM", e);
        }
    }

    /**
     * Decodes a PEM block to its raw DER content bytes (header/footer stripped,
     * base64 decoded). Reads the first PEM object in the input.
     */
    public static byte[] pemToDer(String pem) {
        try (PemReader reader = new PemReader(new StringReader(pem))) {
            PemObject obj = reader.readPemObject();
            if (obj == null) {
                throw new IllegalArgumentException("No PEM block found");
            }
            return obj.getContent();
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid PEM: " + e.getMessage(), e);
        }
    }

    public static byte[] base64Decode(String b64) {
        return Base64.getMimeDecoder().decode(b64);
    }

    public static String base64Encode(byte[] der) {
        return Base64.getEncoder().encodeToString(der);
    }
}
