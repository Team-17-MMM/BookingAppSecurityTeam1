package com.pki.security.PKISecurity.service;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;

import com.pki.security.PKISecurity.domain.*;
import com.pki.security.PKISecurity.dto.CertificateDataDTO;
import com.pki.security.PKISecurity.dto.CertificateTableDTO;
import com.pki.security.PKISecurity.dto.UserCertificateDTO;
import com.pki.security.PKISecurity.manager.StoreManager;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import org.bouncycastle.asn1.x500.X500Name;


import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class PKIService implements IPKIService {
    private final StoreManager storeManager = new StoreManager();
    @Override
    public CertificateRequest issueCertificate(CertificateRequest certificateRequest) {
        return null;
    }

    @Override
    public X509Certificate createCertificate(CertificateDataDTO userCertificateDTO) {

        X500Name subjectName = generateName(userCertificateDTO.getSubject());
        X500Name issuerName = generateName(userCertificateDTO.getIssuer());
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
                getPublicKeyFromBase64(userCertificateDTO.getSubject().getPublicKeyBase64())
        );

        List<String> extensions = new ArrayList<>();
        extensions = userCertificateDTO.getExtensions();

        setExtensions(certBuilder, extensions, subjectName, issuerName);


        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        builder.setProvider("BC");

        String fileName = "D:\\Faks\\V Semestar\\Serverske\\BookingAppServerTeam17\\BookingApp\\src\\main\\resources\\keys\\" + userCertificateDTO.getIssuer().getEmail().split("@")[0];
        String privateKey = this.readPasswordFromFile(fileName);
        try {
            ContentSigner contentSigner = builder.build(getPrivateKeyFromBase64(privateKey));
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");

            String keystoreFileName = "src/main/resources/static/" + userCertificateDTO.getIssuer().getEmail().split("@")[0] + ".jks";
            String password = this.readPasswordFromFile("src/main/resources/passwords/" + userCertificateDTO.getIssuer().getEmail().split("@")[0]);
            storeManager.getKeyStoreWriter().loadKeyStore(keystoreFileName, password.toCharArray());
            storeManager.getKeyStoreWriter().write("cert1", getPrivateKeyFromBase64(privateKey), password.toCharArray(), certConverter.getCertificate(certHolder));
            storeManager.getKeyStoreWriter().saveKeyStore("src/main/resources/static/" + userCertificateDTO.getIssuer().getEmail().split("@")[0] + ".jks", password.toCharArray());
            return certConverter.getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }


    private void createKeyStore(UserCertificateDTO userCertificateDTO){
        String keystoreFileName = "src/main/resources/static/" + userCertificateDTO.getEmail().split("@")[0] + ".jks";
        String keystorePassword = this.generateRandomPassword();
        this.writePasswordToFile("src/main/resources/passwords/" + userCertificateDTO.getEmail().split("@")[0], keystorePassword);
        try {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, keystorePassword.toCharArray());
        try (OutputStream keystoreOutputStream = new FileOutputStream(keystoreFileName)) {
                keyStore.store(keystoreOutputStream, keystorePassword.toCharArray());
        }
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            e.printStackTrace();
        }
    }


    private void writePasswordToFile(String filename, String password) {
        try {
            File file = new File(filename);
            file.delete();
            file.createNewFile();

            FileWriter writer = new FileWriter(file);
            writer.write(password);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private void setExtensions(X509v3CertificateBuilder certBuilder, List<String> extensions, X500Name subjectName, X500Name issuerName) {
        if(extensions.isEmpty()){
            try{
                certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
            }catch (Exception e) {
                throw new RuntimeException("Error adding extension", e);
            }
        }
        for (String extension : extensions) {
            try {
                switch (extension) {
                    case "BASIC_CONSTRAINTS":
                        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
                        break;
                    case "KEY_USAGE":
                        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
                        break;
                    case "SUBJECT_KEY_IDENTIFIER":
                        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(new byte[20]));
                        break;
                    case "SUBJECT_ALTERNATIVE_NAME":
                        GeneralName[] subjectAltNames = new GeneralName[2];
                        subjectAltNames[0] = new GeneralName(GeneralName.dNSName, subjectName.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString());
                        subjectAltNames[1] = new GeneralName(GeneralName.rfc822Name, subjectName.getRDNs(BCStyle.E)[0].getFirst().getValue().toString());
                        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, new org.bouncycastle.asn1.x509.GeneralNames(subjectAltNames));
                        break;
                    case "AUTHORITY_KEY_IDENTIFIER":
                        org.bouncycastle.asn1.x509.AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier((byte[]) null);
                        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
                        break;
                    default:
                        throw new IllegalArgumentException("Invalid extension: " + extension);
                }
            } catch (Exception e) {
                throw new RuntimeException("Error adding extension: " + extension, e);
            }
        }
    }

    private PublicKey getPublicKeyFromBase64(String publicKeyBase64) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64 encoded string", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorithm not supported", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid key specification", e);
        }
    }

    public static PrivateKey getPrivateKeyFromBase64(String privateKeyBase64) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            return privateKey;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64 encoded string", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorithm not supported", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Invalid key specification", e);
        }
    }


    private X500Name generateName(UserCertificateDTO name) {
        System.out.println(name.getFullName());
        System.out.println(name.getLastname());
        System.out.println(name.getName());
        System.out.println(name.getOrganization());
        System.out.println(name.getOrganizationalUnit());
        System.out.println(name.getCountry());
        System.out.println(name.getEmail());
        System.out.println(name.getUserId());
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
    public List<CertificateTableDTO> getAllCertificates() {
        List<CertificateTableDTO> certificateTableDTOs = new ArrayList<>();
        for (Certificate certificate : storeManager.getKeyStoreReader().getAllCertificates("src/main/resources/static/superadmin.jks", "-Cy@ichw6^16")) {
            certificateTableDTOs.add(new CertificateTableDTO(certificate));
        }
        return certificateTableDTOs;
    }

    @Override
    public com.pki.security.PKISecurity.domain.Certificate getCertificate(String id) {
        return null;
    }

    @Override
    public List<CertificateTableDTO> getAllIntermediateCertificates() {
        List<CertificateTableDTO> certificateTableDTOs = new ArrayList<>();
        for (Certificate certificate : storeManager.getKeyStoreReader().getAllIntermediateCertificates("src/main/resources/static/superadmin.jks", "-Cy@ichw6^16")) {
            certificateTableDTOs.add(new CertificateTableDTO(certificate));
        }
        return certificateTableDTOs;
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

    private String readPasswordFromFile(String filename) {
        try {
            return Files.readString(Paths.get(filename));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String generateRandomPassword() {
        int length = 12;
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(chars.length());
            sb.append(chars.charAt(randomIndex));
        }
        return sb.toString();
    }

    public X509Certificate createRootCertificate(CertificateDataDTO certificateDataDTO) {
        this.createKeyStore(certificateDataDTO.getSubject());

        X500Name subjectName = generateName(certificateDataDTO.getSubject());
        X500Name issuerName = generateName(certificateDataDTO.getIssuer());
        Date startDate = Date.from(Instant.now());
        Date endDate = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                getPublicKeyFromBase64(certificateDataDTO.getSubject().getPublicKeyBase64())
        );

        String fileName = "D:\\Faks\\V Semestar\\Serverske\\BookingAppServerTeam17\\BookingApp\\src\\main\\resources\\keys\\" + certificateDataDTO.getIssuer().getEmail().split("@")[0];
        String privateKey = this.readPasswordFromFile(fileName);
        String keystoreFileName = "src/main/resources/static/" + certificateDataDTO.getIssuer().getEmail().split("@")[0] + ".jks";
        String password = this.readPasswordFromFile("src/main/resources/passwords/" + certificateDataDTO.getIssuer().getEmail().split("@")[0]);

        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        builder.setProvider("BC");
        try{
            ContentSigner contentSigner = builder.build(getPrivateKeyFromBase64(privateKey));
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");
            storeManager.getKeyStoreWriter().loadKeyStore(keystoreFileName, password.toCharArray());

            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(new byte[20]));

            storeManager.getKeyStoreWriter().write(certificateDataDTO.getSubject().getEmail(), getPrivateKeyFromBase64(privateKey), password.toCharArray(), certConverter.getCertificate(certHolder));
            storeManager.getKeyStoreWriter().saveKeyStore("src/main/resources/static/" + certificateDataDTO.getSubject().getEmail().split("@")[0] + ".jks", password.toCharArray());
            return certConverter.getCertificate(certHolder);

        }catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        }
    }

}
