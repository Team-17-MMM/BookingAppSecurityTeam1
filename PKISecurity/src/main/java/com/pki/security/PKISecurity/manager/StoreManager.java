package com.pki.security.PKISecurity.manager;

import com.pki.security.PKISecurity.keystores.KeyStoreReader;
import com.pki.security.PKISecurity.keystores.KeyStoreWriter;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class StoreManager {
    private KeyStoreReader keyStoreReader;
    private KeyStoreWriter keyStoreWriter;

    public StoreManager(){
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();
    }
}