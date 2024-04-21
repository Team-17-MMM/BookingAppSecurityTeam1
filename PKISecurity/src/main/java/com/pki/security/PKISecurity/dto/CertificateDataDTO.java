package com.pki.security.PKISecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class CertificateDataDTO {
    private UserCertificateDTO subject;
    private UserCertificateDTO issuer;
    private List<String> extensions;
}
