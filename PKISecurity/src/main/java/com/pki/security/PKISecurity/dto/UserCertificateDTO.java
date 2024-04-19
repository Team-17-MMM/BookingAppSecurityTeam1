package com.pki.security.PKISecurity.dto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.PublicKey;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserCertificateDTO {
    private String userId;
    private String fullName;
    private String name;
    private String lastname;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;
    private String publicKeyBase64; // Base64 encoded string representation of the public key

    public UserCertificateDTO(UserDTO user) {
        this.userId = user.getUserID().toString();
        this.fullName = user.getName() + " " + user.getLastname();
        this.name = user.getName();
        this.lastname = user.getLastname();
        this.organization = "BookingApp";
        this.organizationalUnit = "IT";
        this.country = "RS";
        this.email = user.getUsername();
        this.publicKeyBase64 = null;
    }
}
