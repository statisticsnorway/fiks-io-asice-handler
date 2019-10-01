package no.ks.fiks.io.asice;

import no.ks.fiks.io.asice.read.EncryptedAsicReader;
import no.ks.fiks.io.asice.write.EncryptedAsicWriter;

import java.security.PrivateKey;

public final class AsicHandlerBuilder {
    private PrivateKey privatNokkel;
    private EncryptedAsicWriter encryptedAsicWriter;
    private EncryptedAsicReader encryptedAsicReader;

    private AsicHandlerBuilder() {
    }

    public static AsicHandlerBuilder create() {
        return new AsicHandlerBuilder();
    }

    public AsicHandlerBuilder withPrivatNokkel(PrivateKey privatNokkel) {
        this.privatNokkel = privatNokkel;
        return this;
    }

    public AsicHandlerBuilder withEncryptedAsicWriter(EncryptedAsicWriter encryptedAsicWriter) {
        this.encryptedAsicWriter = encryptedAsicWriter;
        return this;
    }

    public AsicHandlerBuilder withEncryptedAsicReader(EncryptedAsicReader encryptedAsicReader) {
        this.encryptedAsicReader = encryptedAsicReader;
        return this;
    }

    public AsicHandler build() {
        return new AsicHandler(privatNokkel, encryptedAsicWriter, encryptedAsicReader);
    }
}
