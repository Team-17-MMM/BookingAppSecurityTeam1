package com.pki.security.PKISecurity.controller;

import com.pki.security.PKISecurity.enums.ExtensionType;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"/extensions"})
@CrossOrigin
public class ExtensionController {
    @GetMapping(produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<List<String>> getAllExtensions() {
        // Retrieve the list of extensions from your data source
        List<String> extensions = Arrays.stream(ExtensionType.values())
                .map(Enum::name)
                .collect(Collectors.toList());

        return new ResponseEntity<>(extensions, HttpStatus.OK);
    }
}
