package no.ks.fiks.io.asice.model;

import com.google.common.base.Preconditions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;

public final class KeystoreHolderBuilder {
    private KeyStore keyStore;
    private String keyStorePassword;
    private String keyAlias;
    private String keyPassword;

    private KeystoreHolderBuilder() {
    }

    public static KeystoreHolderBuilder create() {
        return new KeystoreHolderBuilder();
    }

    public KeystoreHolderBuilder withKeyStore(final KeyStore keyStore) {
        this.keyStore = keyStore;
        return this;
    }


    public KeystoreHolderBuilder withKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
        return this;
    }

    public KeystoreHolderBuilder withKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
        return this;
    }

    public KeystoreHolderBuilder withKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
        return this;
    }

    public KeystoreHolder build() {
        Preconditions.checkNotNull(keyStorePassword);
        Preconditions.checkNotNull(keyStore);
        if(Arrays.stream(Security.getProviders()).noneMatch(p -> BouncyCastleProvider.class.equals(p))) {
            Security.addProvider(new BouncyCastleProvider());
        }

        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            keyStore.store(output, keyStorePassword.toCharArray());
            return new KeystoreHolder(output.toByteArray(), keyStorePassword, keyAlias, keyPassword);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }
}
