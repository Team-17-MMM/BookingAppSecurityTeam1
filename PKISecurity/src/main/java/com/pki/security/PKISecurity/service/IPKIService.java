package com.pki.security.PKISecurity.service;

import com.pki.security.PKISecurity.domain.Certificate;
import com.pki.security.PKISecurity.domain.CertificateRequest;

public interface IPKIService {

    CertificateRequest issueCertificate(CertificateRequest certificateRequest);

    Certificate createCertificate(String id);

    Certificate getCertificate(String id);

    Boolean revokeCertificate(String id);

    Boolean deleteCertificate(String id);

    Boolean isCertificateValid(String id);

    Boolean deleteCertificateRequest(String id);
}
