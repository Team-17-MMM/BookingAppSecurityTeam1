package com.pki.security.PKISecurity.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.security.PublicKey;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class CertificateRequest {
    private String subject;
    private PublicKey publicKey;
    private List<Extension> extensions;
}
