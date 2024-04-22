package com.pki.security.PKISecurity.keystores;

import com.pki.security.PKISecurity.domain.Issuer;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;


@Component
public class KeyStoreReader {
    //KeyStore je Java klasa za citanje specijalizovanih datoteka koje se koriste za cuvanje kljuceva
    //Tri tipa entiteta koji se obicno nalaze u ovakvim datotekama su:
    // - Sertifikati koji ukljucuju javni kljuc
    // - Privatni kljucevi
    // - Tajni kljucevi, koji se koriste u simetricnima siframa
    private KeyStore keyStore;

    public KeyStoreReader() {
        try {
            keyStore = KeyStore.getInstance("JKS", "SUN");
        } catch (KeyStoreException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    /**
     * Zadatak ove funkcije jeste da ucita podatke o izdavaocu i odgovarajuci privatni kljuc.
     * Ovi podaci se mogu iskoristiti da se novi sertifikati izdaju.
     *
     * @param keyStoreFile - datoteka odakle se citaju podaci
     * @param alias        - alias putem kog se identifikuje sertifikat izdavaoca
     * @param password     - lozinka koja je neophodna da se otvori key store
     * @param keyPass      - lozinka koja je neophodna da se izvuce privatni kljuc
     * @return - podatke o izdavaocu i odgovarajuci privatni kljuc
     */
    public Issuer readIssuerFromStore(String keyStoreFile, String alias, char[] password, char[] keyPass) {
        try {
            //Datoteka se ucitava
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            keyStore.load(in, password);

            //Iscitava se sertifikat koji ima dati alias
            Certificate cert = keyStore.getCertificate(alias);

            //Iscitava se privatni kljuc vezan za javni kljuc koji se nalazi na sertifikatu sa datim aliasom
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPass);

            X500Name issuerName = new JcaX509CertificateHolder((X509Certificate) cert).getSubject();
            return new Issuer(privateKey, cert.getPublicKey(), issuerName);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException |
                 IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Ucitava sertifikat is KS fajla
     */
    public Certificate readCertificate(String keyStoreFile, String keyStorePass, String alias) {
        try {
            //kreiramo instancu KeyStore
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            //ucitavamo podatke
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            ks.load(in, keyStorePass.toCharArray());

            if (ks.isKeyEntry(alias)) {
                Certificate cert = ks.getCertificate(alias);
                return cert;
            }
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException |
                 IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Ucitava privatni kljuc is KS fajla
     */
    public PrivateKey readPrivateKey(String keyStoreFile, String keyStorePass, String alias, String pass) {
        try {
            //kreiramo instancu KeyStore
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            //ucitavamo podatke
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            ks.load(in, keyStorePass.toCharArray());

            if (ks.isKeyEntry(alias)) {
                PrivateKey pk = (PrivateKey) ks.getKey(alias, pass.toCharArray());
                return pk;
            }
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException |
                 IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static List<Certificate> getAllCertificates(String keyStoreFolder, String passwordsFolder) {
        List<Certificate> certificates = new ArrayList<>();
        File folder = new File(keyStoreFolder);
        File[] files = folder.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    try {
                        // remove file extension
                        String fileName = file.getName().substring(0, file.getName().lastIndexOf('.'));
                        certificates.addAll(getCertificatesFromFile(file.getAbsolutePath(), Files.readString(Paths.get(passwordsFolder + fileName))));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        return certificates;
    }

    private static List<Certificate> getCertificatesFromFile(String keyStoreFile, String keyStorePass) {
        List<Certificate> certificates = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            FileInputStream in = new FileInputStream(keyStoreFile);
            ks.load(in, keyStorePass.toCharArray());
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = ks.getCertificate(alias);
                certificates.add(cert);
            }
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException |
                 CertificateException | IOException e) {
            e.printStackTrace();
        }
        return certificates;
    }

    public static Certificate getHostCertificate(String keyStoreFolder, String passwordsFolder, String alias) {
        File folder = new File(keyStoreFolder);
        File[] files = folder.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    try {
                        // remove file extension
                        String fileName = file.getName().substring(0, file.getName().lastIndexOf('.'));
                        Certificate cert = getCertificateFromFileByAlias(file.getAbsolutePath(), Files.readString(Paths.get(passwordsFolder + fileName)),alias);
                        if (cert != null){
                            return cert;
                        }
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        return null;
    }

    private static Certificate getCertificateFromFileByAlias(String keyStoreFile, String keyStorePass, String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            FileInputStream in = new FileInputStream(keyStoreFile);
            ks.load(in, keyStorePass.toCharArray());
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                if(Objects.equals(aliases.nextElement(), alias)){
                    return ks.getCertificate(alias);
                }

            }
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException |
                 CertificateException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<Certificate> getAllIntermediateCertificates(String keyStoreFolder, String passwordsFolder) {
        List<Certificate> certificates = new ArrayList<>();
        File folder = new File(keyStoreFolder);
        File[] files = folder.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    try {
                        // remove file extension
                        String fileName = file.getName().substring(0, file.getName().lastIndexOf('.'));
                        certificates.addAll(getIntermediateCertificatesFromFile(file.getAbsolutePath(), Files.readString(Paths.get(passwordsFolder + fileName))));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        return certificates;
    }

    private Collection<? extends Certificate> getIntermediateCertificatesFromFile(String absolutePath, String s) {
        List<Certificate> certificates = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            FileInputStream in = new FileInputStream(absolutePath);
            ks.load(in, s.toCharArray());
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = ks.getCertificate(alias);
                if (isIntermediateCertificate((X509Certificate) cert)) {
                    certificates.add(cert);
                }
            }
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException |
                 CertificateException | IOException e) {
            e.printStackTrace();
        }
        return certificates;
    }


    public boolean isIntermediateCertificate(X509Certificate cert) {
        System.out.println(cert.getBasicConstraints());
        return cert.getBasicConstraints() != -1;
    }

}