package no.ks.fiks.io.asice;

import no.ks.fiks.io.asice.model.Content;
import no.ks.fiks.io.asice.read.EncryptedAsicReader;
import no.ks.fiks.io.asice.write.EncryptedAsicWriter;

import java.io.InputStream;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.ZipInputStream;

import static com.google.common.base.Preconditions.checkNotNull;

public class AsicHandler {
    private final PrivateKey privatNokkel;
    private final EncryptedAsicWriter encryptedAsicWriter;
    private final EncryptedAsicReader encryptedAsicReader;

    AsicHandler(final PrivateKey privatNokkel,
                final EncryptedAsicWriter encryptedAsicWriter,
                final EncryptedAsicReader encryptedAsicReader) {
        checkNotNull(privatNokkel);
        this.privatNokkel = privatNokkel;

        checkNotNull(encryptedAsicWriter);
        this.encryptedAsicWriter = encryptedAsicWriter;

        checkNotNull(encryptedAsicReader);
        this.encryptedAsicReader = encryptedAsicReader;
    }

    InputStream encrypt(final X509Certificate mottakerCert, final List<Content> payload) {
        checkNotNull(mottakerCert);
        checkNotNull(payload);
        return encryptedAsicWriter.createAndEncrypt(mottakerCert, payload);
    }

    public ZipInputStream decrypt(final InputStream encryptedAsicData) {
        checkNotNull(encryptedAsicData);
        return encryptedAsicReader.decrypt(encryptedAsicData, privatNokkel);
    }

    public void writeDecrypted(final InputStream encryptedAsicData, final Path targetPath) {
        checkNotNull(encryptedAsicData);
        checkNotNull(targetPath);
        encryptedAsicReader.writeDecryptedToPath(encryptedAsicData, privatNokkel, targetPath);
    }

    public static AsicHandlerBuilder builder() {
        return AsicHandlerBuilder.create();
    }


}
