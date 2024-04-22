package com.pki.security.PKISecurity.service;

import com.pki.security.PKISecurity.domain.Certificate;
import com.pki.security.PKISecurity.domain.CertificateRequest;
import com.pki.security.PKISecurity.dto.*;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

public interface IPKIService {

    CertificateRequest issueCertificate(CertificateRequest certificateRequest);

    X509Certificate createCertificate(CertificateDataDTO certificateData);

    Boolean deleteCertificateWithChildren(String id);

    Boolean revokeCertificateWithChildren(String id);

    Boolean isCertificateValid(String id);

    Boolean deleteCertificateRequest(String id);

    KeyPair generateKeyPair();

    List<CertificateTableDTO> getAllCertificates();

    CertificateTableSignatureDTO getHostCertificate(String email);
    Certificate getCertificate(String id);

    List<CertificateTableDTO> getAllIntermediateCertificates();

    X509Certificate createRootCertificate(CertificateDataDTO userCertificateDTO);
}