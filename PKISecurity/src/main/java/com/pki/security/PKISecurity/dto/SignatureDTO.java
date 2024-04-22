package com.pki.security.PKISecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SignatureDTO {
    private List<CertificateTableDTO> data;
    private byte[] signature;
    private String publicKey;
}
