package no.ks.fiks.io.asice;

import no.ks.fiks.io.asice.crypto.DecryptionStreamServiceImpl;
import no.ks.fiks.io.asice.crypto.PipedEncryptionServiceImpl;
import no.ks.fiks.io.asice.model.KeystoreHolder;
import no.ks.fiks.io.asice.read.EncryptedAsicReaderImpl;
import no.ks.fiks.io.asice.sign.SignatureHelperProviderImpl;
import no.ks.fiks.io.asice.write.EncryptedAsicWriterImpl;

import java.security.PrivateKey;
import java.util.concurrent.ExecutorService;

public final class AsicHandlerBuilder {
    private PrivateKey privatNokkel;
    private ExecutorService executorService;
    private KeystoreHolder keystoreHolder;

    private AsicHandlerBuilder() {
    }

    public static AsicHandlerBuilder create() {
        return new AsicHandlerBuilder();
    }

    public AsicHandlerBuilder withPrivatNokkel(PrivateKey privatNokkel) {
        this.privatNokkel = privatNokkel;
        return this;
    }

    public AsicHandlerBuilder withExecutorService(final ExecutorService executorService) {
        this.executorService = executorService;
        return this;
    }

    public AsicHandlerBuilder withKeyStoreHolder(final KeystoreHolder keystoreHolder) {
        this.keystoreHolder = keystoreHolder;
        return this;
    }

    public AsicHandler build() {
        return new AsicHandler(privatNokkel, new EncryptedAsicWriterImpl(new PipedEncryptionServiceImpl(executorService), executorService, new SignatureHelperProviderImpl(keystoreHolder)), new EncryptedAsicReaderImpl(executorService, new DecryptionStreamServiceImpl()));
    }
}
