package com.pki.security.PKISecurity.service;

import com.pki.security.PKISecurity.domain.Certificate;
import com.pki.security.PKISecurity.domain.CertificateRequest;
import com.pki.security.PKISecurity.dto.UserCertificateDTO;
import com.pki.security.PKISecurity.dto.UserDTO;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Map;

public interface IPKIService {

    CertificateRequest issueCertificate(CertificateRequest certificateRequest);

    X509Certificate createCertificate(Map<String, UserCertificateDTO> certificateData);

    Certificate getCertificate(String id);

    Boolean revokeCertificate(String id);

    Boolean deleteCertificate(String id);

    Boolean isCertificateValid(String id);

    Boolean deleteCertificateRequest(String id);

    KeyPair generateKeyPair();
}
