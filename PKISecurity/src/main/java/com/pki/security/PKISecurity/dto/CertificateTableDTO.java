package com.pki.security.PKISecurity.dto;

import com.pki.security.PKISecurity.enums.ExtensionType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x509.Extension;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import java.security.cert.X509Certificate;
import java.util.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CertificateTableDTO {
    private String CAName;
    private String SubjectName;
    private Date startDate;
    private Date endDate;
    private List<String> extensions;
    private BigInteger serialNumber;

    public CertificateTableDTO(Certificate certificate) {
        try {
            byte[] encoded = certificate.getEncoded();
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded));

            this.CAName = x509Certificate.getIssuerX500Principal().getName();
            this.SubjectName = x509Certificate.getSubjectX500Principal().getName();
            this.startDate = x509Certificate.getNotBefore();
            this.endDate = x509Certificate.getNotAfter();
            this.extensions = extractExtensions(x509Certificate);
            this.serialNumber = x509Certificate.getSerialNumber();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    private static final Map<String, String> EXTENSION_NAMES = new HashMap<>();
    static {
        // Add mappings for known extension OID numbers to names
        EXTENSION_NAMES.put(Extension.basicConstraints.getId(), "BASIC_CONSTRAINTS");
        EXTENSION_NAMES.put(Extension.subjectKeyIdentifier.getId(), "SUBJECT_KEY_IDENTIFIER");
        EXTENSION_NAMES.put(Extension.keyUsage.getId(), "KEY_USAGE");
        EXTENSION_NAMES.put(Extension.subjectAlternativeName.getId(), "SUBJECT_ALTERNATIVE_NAME");
        EXTENSION_NAMES.put(Extension.issuerAlternativeName.getId(), "ISSUER_ALTERNATIVE_NAME");
        EXTENSION_NAMES.put(Extension.authorityKeyIdentifier.getId(), "AUTHORITY_KEY_IDENTIFIER");
    }

    private List<String> extractExtensions(X509Certificate x509Certificate) {
        List<String> extractedExtensions = new ArrayList<>();
        try {
            // Get critical and non-critical extension OIDs
            Set<String> criticalExtensions = x509Certificate.getCriticalExtensionOIDs();
            Set<String> nonCriticalExtensions = x509Certificate.getNonCriticalExtensionOIDs();

            // Check critical extensions
            if (criticalExtensions != null) {
                for (String oid : criticalExtensions) {
                    // Get the name from the map if available, otherwise use the OID number
                    String extensionName = EXTENSION_NAMES.getOrDefault(oid, oid);
                    extractedExtensions.add(extensionName);
                }
            }

            // Check non-critical extensions
            if (nonCriticalExtensions != null) {
                for (String oid : nonCriticalExtensions) {
                    // Get the name from the map if available, otherwise use the OID number
                    String extensionName = EXTENSION_NAMES.getOrDefault(oid, oid);
                    extractedExtensions.add(extensionName);
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        return extractedExtensions;
    }

    private ExtensionType getExtensionType(String oid) {
        for (ExtensionType type : ExtensionType.values()) {
            if (type.name().equals(oid)) {
                return type;
            }
        }
        return null;
    }


}