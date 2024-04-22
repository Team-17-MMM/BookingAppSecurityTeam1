package com.pki.security.PKISecurity.service;

import com.pki.security.PKISecurity.domain.Certificate;
import com.pki.security.PKISecurity.domain.CertificateRequest;
import com.pki.security.PKISecurity.dto.CertificateDataDTO;
import com.pki.security.PKISecurity.dto.CertificateTableDTO;
import com.pki.security.PKISecurity.dto.UserCertificateDTO;
import com.pki.security.PKISecurity.dto.UserDTO;

import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

public interface IPKIService {

    CertificateRequest issueCertificate(CertificateRequest certificateRequest);

    X509Certificate createCertificate(CertificateDataDTO certificateData);

    Boolean revokeCertificate(String id);

    Boolean deleteCertificateWithChildren(String id);

    Boolean revokeCertificateWithChildren(String id);

    Boolean isCertificateValid(String id);

    Boolean deleteCertificateRequest(String id);

    KeyPair generateKeyPair();

    List<CertificateTableDTO> getAllCertificates();

    CertificateTableDTO getHostCertificate(String email);
    Certificate getCertificate(String id);

    List<CertificateTableDTO> getAllIntermediateCertificates();

    X509Certificate createRootCertificate(CertificateDataDTO userCertificateDTO);
}