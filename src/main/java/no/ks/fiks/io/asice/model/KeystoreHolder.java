package no.ks.fiks.io.asice.model;

import lombok.NonNull;

import java.util.Arrays;

public class KeystoreHolder {

    private final byte[] keyStoreBytes;
    private final String keyStorePassword;
    private final String keyAlias;
    private final String keyPassword;

    public KeystoreHolder(@NonNull byte[] keyStoreBytes, @NonNull String keyStorePassword, @NonNull String keyAlias, @NonNull String keyPassword) {
        this.keyStoreBytes = Arrays.copyOf(keyStoreBytes, keyStoreBytes.length);


        this.keyStorePassword = keyStorePassword;
        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
    }

    public byte[] getKeyStoreBytes() {
        return Arrays.copyOf(keyStoreBytes, keyStoreBytes.length);
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public static KeystoreHolderBuilder builder() {
        return KeystoreHolderBuilder.create();
    }

    @Override
    public String toString() {
        return "KeystoreHolder{" +
            "keyStoreBytes=" + Arrays.toString(keyStoreBytes) +
            ", keyStorePassword='*****'" +
            ", keyAlias='" + keyAlias + '\'' +
            ", keyPassword='*****'" +
            '}';
    }
}
