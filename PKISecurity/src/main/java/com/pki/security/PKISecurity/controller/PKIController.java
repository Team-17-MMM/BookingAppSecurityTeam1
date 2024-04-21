package com.pki.security.PKISecurity.controller;

import com.pki.security.PKISecurity.domain.Certificate;
import com.pki.security.PKISecurity.domain.CertificateRequest;
import com.pki.security.PKISecurity.dto.*;
import com.pki.security.PKISecurity.service.IPKIService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.awt.image.Kernel;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/pki")
@CrossOrigin
public class PKIController {
    @Autowired
    private IPKIService pkiService;

    @PostMapping("/issueCertificate")
    public ResponseEntity<CertificateRequest> issueCertificate(@RequestBody CertificateRequest certificateRequest) {
        try {
            CertificateRequest certificate = pkiService.issueCertificate(certificateRequest);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @PostMapping(value = {"/createCertificate"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Boolean> createCertificate(@RequestBody CertificateDataDTO certificateData){
        try {
            X509Certificate certificate = pkiService.createCertificate(certificateData);
            return ResponseEntity.ok(certificate != null);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

    @PostMapping(value = {"/createRootCertificate"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Boolean> createRootCertificate(@RequestBody CertificateDataDTO certificateData){
        try {
            X509Certificate certificate = pkiService.createRootCertificate(certificateData);
            return ResponseEntity.ok(certificate != null);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

//    @PostMapping(value = {"/generateRoot"}, produces = {MediaType.APPLICATION_JSON_VALUE})
//    public ResponseEntity<Boolean> generateRootCertificate(@RequestBody CertificateDataDTO certificateData){
//        try {
//            X509Certificate certificate = pkiService.createRootCertificate(certificateData);
//            return ResponseEntity.ok(certificate != null);
//        } catch (Exception e) {
//            System.out.println(e.getMessage());
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
//        }
//    }

    @GetMapping(value = {"/getCertificate/{id}"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Certificate> getCertificate(@PathVariable("id") String id){
        try {
            Certificate certificate = pkiService.getCertificate(id);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @GetMapping(value = {"/getCertificate"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<List<CertificateTableDTO>> getAllCertificates(){
        try {
            return ResponseEntity.ok(pkiService.getAllCertificates());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @GetMapping(value = {"/getIntermediateCertificate"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<List<CertificateTableDTO>> getAllIntermediateCertificates(){
        try {
            return ResponseEntity.ok(pkiService.getAllIntermediateCertificates());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @GetMapping(value = {"/revokeCertificate/{id}"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Boolean> revokeCertificate(@PathVariable("id") String id){
        try {
            Boolean certificate = pkiService.revokeCertificate(id);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

    @DeleteMapping(value = {"/deleteCertificate/{id}"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Boolean> deleteCertificate(@PathVariable("id") String id){
        try {
            Boolean certificate = pkiService.deleteCertificate(id);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

    @GetMapping(value = {"/isCertificateValid/{id}"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Boolean> isCertificateValid(@PathVariable("id") String id){
        try {
            Boolean certificate = pkiService.isCertificateValid(id);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

    @DeleteMapping(value = {"/deleteCertificateRequest/{id}"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<Boolean> deleteCertificateRequest(@PathVariable("id") String id){
        try {
            Boolean certificate = pkiService.deleteCertificateRequest(id);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(false);
        }
    }

    @GetMapping(value = {"/generateKeyPair"}, produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<KeyPairDTO> generateKeyPair(){
        try {
            KeyPair keyPair = pkiService.generateKeyPair();
            return ResponseEntity.ok(new KeyPairDTO(keyPair.getPublic(), keyPair.getPrivate()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
}
