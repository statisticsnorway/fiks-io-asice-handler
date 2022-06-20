package no.ks.fiks.io.asice;

import no.ks.fiks.io.asice.model.KeystoreHolder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class AsicHandlerBuilderTest {

    @DisplayName("Opprett AsicHandler")
    @Test
    void create(@Mock ExecutorService executorService, @Mock PrivateKey privateKey) {
        final AsicHandler asicHandler = AsicHandlerBuilder.create()
            .withExecutorService(executorService)
            .withPrivatNokkel(privateKey)
            .withKeyStoreHolder(getKeystoreHolder())
            .build();
        assertThat(asicHandler).isNotNull();
        verifyNoInteractions(executorService, privateKey);
    }

    @DisplayName("Tester håndtering av null")
    @Test
    void buildNotComplete(@Mock ExecutorService executorService, @Mock PrivateKey privateKey) {
        assertThrows(NullPointerException.class, () -> AsicHandlerBuilder.create().build());
        assertThrows(NullPointerException.class, () -> AsicHandlerBuilder.create().withPrivatNokkel(privateKey).build());
        assertThrows(NullPointerException.class, () -> AsicHandlerBuilder.create().withPrivatNokkel(privateKey).withExecutorService(executorService).build());
        assertThrows(NullPointerException.class, () -> AsicHandlerBuilder.create().withPrivatNokkel(privateKey).withKeyStoreHolder(getKeystoreHolder()).build());
    }


    private KeystoreHolder getKeystoreHolder()  {
        try {
            return KeystoreHolder.builder().withKeyAlias("et alias")
                .withKeyPassword("PASSWORD")
                .withKeyStorePassword("PASSWORD")
                .withKeyStore(getKeyStore())
                .build();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException("Kunne ikke sette opp KeyStore", e);
        }
    }

    private KeyStore getKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(this.getClass().getClassLoader().getResourceAsStream("alice-virksomhetssertifikat.p12"), "PASSWORD".toCharArray());
        return keyStore;
    }
}