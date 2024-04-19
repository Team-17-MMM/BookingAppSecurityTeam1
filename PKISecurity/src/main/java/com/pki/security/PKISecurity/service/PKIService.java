package com.pki.security.PKISecurity.service;

import com.pki.security.PKISecurity.domain.*;
import com.pki.security.PKISecurity.domain.Certificate;
import com.pki.security.PKISecurity.dto.UserCertificateDTO;
import com.pki.security.PKISecurity.manager.StoreManager;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import org.bouncycastle.asn1.x500.X500Name;


import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

@Service
public class PKIService implements IPKIService {
    private final StoreManager storeManager = new StoreManager();
    @Override
    public CertificateRequest issueCertificate(CertificateRequest certificateRequest) {
        return null;
    }

    @Override
    public X509Certificate createCertificate(Map<String, UserCertificateDTO> userCertificateDTO) {
//        Certificate certificateSave;
//        try {
//
//            X500Name subjectName = generateSubject();
//
//
////            Issuer issuer = generateIssuer();
////            Subject subject = generateSubject();
//
////            //Datumi od kad do kad vazi sertifikat
////            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
////            Date startDate = sdf.parse("2023-03-25");
////            Date endDate = sdf.parse("2028-03-25");
////
////            X509Certificate certificate = CertificateGenerator.generateCertificate(subject,
////                    issuer, startDate, endDate, "1");
////
////
////            certificateSave = new Certificate(subject, issuer,
////                    "1", startDate, endDate, certificate);
////
////            System.out.println("Cuvanje certifikata u jks fajl:");
////            storeManager.getKeyStoreWriter().loadKeyStore("src/main/resources/static/keystore.jks",  "password".toCharArray());
////            PrivateKey pk = certificateSave.getIssuer().getPrivateKey();
////            storeManager.getKeyStoreWriter().write("cert1", pk, "password".toCharArray(), certificateSave.getX509Certificate());
////            storeManager.getKeyStoreWriter().saveKeyStore("src/main/resources/static/keystore.jks",  "password".toCharArray());
////            System.out.println("Cuvanje certifikata u jks fajl zavrseno.");
////
////            System.out.println("Ucitavanje sertifikata iz jks fajla:");
////            java.security.cert.Certificate loadedCertificate = storeManager.getKeyStoreReader().readCertificate("src/main/resources/static/keystore.jks", "password", "cert1");
////            System.out.println(loadedCertificate);
//        } catch (ParseException e) {
//            e.printStackTrace();
//        }
//

        X500Name subjectName = generateName(userCertificateDTO.get("subject"));
        X500Name issuerName = generateName(userCertificateDTO.get("issuer"));
        KeyPair keyPair = generateKeyPair();
        Date startDate = Date.from(Instant.now());
        Date endDate = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                userCertificateDTO.get("subject").getPublicKey()
        );

//        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
//        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
//        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        builder.setProvider("BC");
        try {
            ContentSigner contentSigner = builder.build(keyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");
            storeManager.getKeyStoreWriter().loadKeyStore("src/main/resources/static/keystore.jks", "password".toCharArray());
            storeManager.getKeyStoreWriter().write("cert1", keyPair.getPrivate(), "password".toCharArray(), certConverter.getCertificate(certHolder));
            return certConverter.getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private X500Name generateName(UserCertificateDTO name) {
        return new X500Name(
                "CN=" + name.getFullName() +
                ", SURNAME=" + name.getLastname() +
                ", GIVENNAME=" + name.getName() +
                ", O=" + name.getOrganization() +
                ", OU=" + name.getOrganizationalUnit() +
                ", C=" + name.getCountry() +
                ", E=" + name.getEmail() +
                ", UID=" + name.getUserId()
        );
    }


    @Override
    public Certificate getCertificate(String id) {
        return null;
    }

    @Override
    public Boolean revokeCertificate(String id) {
        return null;
    }

    @Override
    public Boolean deleteCertificate(String id) {
        return null;
    }

    @Override
    public Boolean isCertificateValid(String id) {
        return null;
    }

    @Override
    public Boolean deleteCertificateRequest(String id) {
        return null;
    }


//    public Subject generateSubject(UserCertificateDTO userCertificateDTO) {
//        KeyPair keyPairSubject = generateKeyPair();
//
//        //klasa X500NameBuilder pravi X500Name objekat koji predstavlja podatke o vlasniku
//        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
////        builder.addRDN(BCStyle.CN, userDTO.getName() + " " + userDTO.getLastname());
////        builder.addRDN(BCStyle.SURNAME, userDTO.getLastname());
////        builder.addRDN(BCStyle.GIVENNAME, userDTO.getName());
////        builder.addRDN(BCStyle.O, "Team 1");
////        builder.addRDN(BCStyle.OU, "Bakiji");
////        builder.addRDN(BCStyle.C, "RS");
////        builder.addRDN(BCStyle.E, userDTO.getUsername());
////        //UID (USER ID) je ID korisnika
////        builder.addRDN(BCStyle.UID, userDTO.getUserID().toString());
//
//        return new Subject(keyPairSubject.getPublic(), builder.build());
//    }
//
//    public Issuer generateIssuer() {
//        KeyPair kp = generateKeyPair();
//        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.CN, "IT sluzba");
//        builder.addRDN(BCStyle.SURNAME, "sluzba");
//        builder.addRDN(BCStyle.GIVENNAME, "IT");
//        builder.addRDN(BCStyle.O, "UNS-FTN");
//        builder.addRDN(BCStyle.OU, "Katedra za informatiku");
//        builder.addRDN(BCStyle.C, "RS");
//        builder.addRDN(BCStyle.E, "itsluzba@uns.ac.rs");
//        //UID (USER ID) je ID korisnika
//        builder.addRDN(BCStyle.UID, "654321");
//
//        //Kreiraju se podaci za issuer-a, sto u ovom slucaju ukljucuje:
//        // - privatni kljuc koji ce se koristiti da potpise sertifikat koji se izdaje
//        // - podatke o vlasniku sertifikata koji izdaje nov sertifikat
//        return new Issuer(kp.getPrivate(), kp.getPublic(), builder.build());
//    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }
}
