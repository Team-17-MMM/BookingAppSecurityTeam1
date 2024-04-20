package com.pki.security.PKISecurity.dto;

import com.pki.security.PKISecurity.enums.ExtensionType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

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
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
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
                    extractedExtensions.add(oid);
                }
            }

            // Check non-critical extensions
            if (nonCriticalExtensions != null) {
                for (String oid : nonCriticalExtensions) {

                    extractedExtensions.add(oid);
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