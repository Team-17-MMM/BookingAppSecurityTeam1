package com.pki.security.PKISecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
public class CertificateTableDTO {
    private String CAName;
    private String SubjectName;
    private Date startDate; //mozda cak i String ovde ne secam se kako bese ovo
    private Date endDate;
    //TODO: i ovde mi treba lista ekstenzija kao enumi List<Extention>(). napravi kako mislis da treba, ja nzm koji su sve extentioni tu
}
