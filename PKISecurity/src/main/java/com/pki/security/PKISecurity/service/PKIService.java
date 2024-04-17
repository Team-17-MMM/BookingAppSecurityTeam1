package com.pki.security.PKISecurity.service;

import com.pki.security.PKISecurity.domain.*;
import com.pki.security.PKISecurity.domain.Certificate;
import com.pki.security.PKISecurity.manager.StoreManager;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Service
public class PKIService implements IPKIService {
    private final StoreManager storeManager = new StoreManager();
    @Override
    public CertificateRequest issueCertificate(CertificateRequest certificateRequest) {
        return null;
    }

    @Override
    public Certificate createCertificate(String id) {
        Certificate certificateSave;
        try {
            Issuer issuer = generateIssuer();
            Subject subject = generateSubject();

            //Datumi od kad do kad vazi sertifikat
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date startDate = sdf.parse("2023-03-25");
            Date endDate = sdf.parse("2028-03-25");

            X509Certificate certificate = CertificateGenerator.generateCertificate(subject,
                    issuer, startDate, endDate, "1");

            certificateSave = new Certificate(subject, issuer,
                    "1", startDate, endDate, certificate);

            System.out.println("Cuvanje certifikata u jks fajl:");
            storeManager.getKeyStoreWriter().loadKeyStore("src/main/resources/static/keystore.jks",  "password".toCharArray());
            PrivateKey pk = certificateSave.getIssuer().getPrivateKey();
            storeManager.getKeyStoreWriter().write("cert1", pk, "password".toCharArray(), certificateSave.getX509Certificate());
            storeManager.getKeyStoreWriter().saveKeyStore("src/main/resources/static/keystore.jks",  "password".toCharArray());
            System.out.println("Cuvanje certifikata u jks fajl zavrseno.");

            System.out.println("Ucitavanje sertifikata iz jks fajla:");
            java.security.cert.Certificate loadedCertificate = storeManager.getKeyStoreReader().readCertificate("src/main/resources/static/keystore.jks", "password", "cert1");
            System.out.println(loadedCertificate);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return null;
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


    public Subject generateSubject() {
        KeyPair keyPairSubject = generateKeyPair();

        //klasa X500NameBuilder pravi X500Name objekat koji predstavlja podatke o vlasniku
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "Ivana Kovacevic");
        builder.addRDN(BCStyle.SURNAME, "Kovacevic");
        builder.addRDN(BCStyle.GIVENNAME, "Ivana");
        builder.addRDN(BCStyle.O, "UNS-FTN");
        builder.addRDN(BCStyle.OU, "Katedra za informatiku");
        builder.addRDN(BCStyle.C, "RS");
        builder.addRDN(BCStyle.E, "kovacevic.ivana@uns.ac.rs");
        //UID (USER ID) je ID korisnika
        builder.addRDN(BCStyle.UID, "123456");

        return new Subject(keyPairSubject.getPublic(), builder.build());
    }

    public Issuer generateIssuer() {
        KeyPair kp = generateKeyPair();
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, "IT sluzba");
        builder.addRDN(BCStyle.SURNAME, "sluzba");
        builder.addRDN(BCStyle.GIVENNAME, "IT");
        builder.addRDN(BCStyle.O, "UNS-FTN");
        builder.addRDN(BCStyle.OU, "Katedra za informatiku");
        builder.addRDN(BCStyle.C, "RS");
        builder.addRDN(BCStyle.E, "itsluzba@uns.ac.rs");
        //UID (USER ID) je ID korisnika
        builder.addRDN(BCStyle.UID, "654321");

        //Kreiraju se podaci za issuer-a, sto u ovom slucaju ukljucuje:
        // - privatni kljuc koji ce se koristiti da potpise sertifikat koji se izdaje
        // - podatke o vlasniku sertifikata koji izdaje nov sertifikat
        return new Issuer(kp.getPrivate(), kp.getPublic(), builder.build());
    }

    private KeyPair generateKeyPair() {
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
