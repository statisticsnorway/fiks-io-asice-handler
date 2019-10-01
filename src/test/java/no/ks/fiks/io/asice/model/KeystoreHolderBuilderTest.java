package no.ks.fiks.io.asice.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class KeystoreHolderBuilderTest {

    @DisplayName("Laster KeyStore")
    @Test
    void withKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        final KeystoreHolder keystoreHolder = KeystoreHolder.builder()
            .withKeyStore(getKeyStore())
            .withKeyStorePassword("PASSWORD")
            .withKeyPassword("PASSWORD")
            .withKeyAlias("et alias")
            .build();
        assertThat(keystoreHolder).hasNoNullFieldsOrProperties();

    }

    private KeyStore getKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("alice-virksomhetssertifikat.p12"), "PASSWORD".toCharArray());
        return keyStore;
    }
}