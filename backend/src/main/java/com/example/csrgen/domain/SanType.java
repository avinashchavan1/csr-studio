package com.example.csrgen.domain;

import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Subject Alternative Name types, mapped to Bouncy Castle GeneralName tags.
 */
public enum SanType {
    DNS(GeneralName.dNSName),
    IP(GeneralName.iPAddress),
    EMAIL(GeneralName.rfc822Name),
    URI(GeneralName.uniformResourceIdentifier);

    private final int generalNameTag;

    SanType(int generalNameTag) {
        this.generalNameTag = generalNameTag;
    }

    public int tag() {
        return generalNameTag;
    }
}
