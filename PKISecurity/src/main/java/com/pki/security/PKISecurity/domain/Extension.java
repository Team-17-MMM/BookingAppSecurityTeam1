package com.pki.security.PKISecurity.domain;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Extension {
    private String oid;
    private byte[] value;

    public Extension(String oid, byte[] value) {
        this.oid = oid;
        this.value = value;
    }
}
