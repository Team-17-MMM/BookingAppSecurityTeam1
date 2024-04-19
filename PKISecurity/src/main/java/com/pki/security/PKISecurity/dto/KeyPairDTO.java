package com.pki.security.PKISecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.PublicKey;

@Getter
@Setter
@AllArgsConstructor
public class KeyPairDTO {
    private String publicKey;
    private String privateKey;

    public KeyPairDTO(PublicKey aPublic, PrivateKey aPrivate) {
        this.publicKey = aPublic.toString();
        this.privateKey = aPrivate.toString();
    }
}
