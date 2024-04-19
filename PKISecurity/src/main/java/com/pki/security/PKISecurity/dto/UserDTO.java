package com.pki.security.PKISecurity.dto;

import com.pki.security.PKISecurity.enums.UserRoleType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Long userID;
    private String username;
    private String password;
    private String name;
    private String lastname;
    private String address;
    private String phone;
    private boolean enabled;
    private UserRoleType userRole;

    public void copyValues(UserDTO user) {
        this.setUsername(user.getUsername());
        this.setName(user.getName());
        this.setLastname(user.getLastname());
        this.setPassword(user.getPassword());
        this.setAddress(user.getAddress());
        this.setPhone(user.getPhone());
        this.setUserRole(user.getUserRole());
        this.setEnabled(user.isEnabled());
    }

    @Override
    public String toString () {
        return "UserDTO{" +
                "userID=" + userID +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", name='" + name + '\'' +
                ", lastname='" + lastname + '\'' +
                ", address='" + address + '\'' +
                ", phone='" + phone + '\'' +
                ", userRole=" + userRole +
                ", enabled=" + enabled +
                '}';
    }
}
