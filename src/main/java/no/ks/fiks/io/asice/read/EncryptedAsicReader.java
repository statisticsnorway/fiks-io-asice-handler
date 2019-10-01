package no.ks.fiks.io.asice.read;

import java.io.InputStream;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.zip.ZipInputStream;

public interface EncryptedAsicReader {

    ZipInputStream decrypt(InputStream encryptedAsicData, PrivateKey privateKey);

    void writeDecryptedToPath(final InputStream encryptedAsicData, PrivateKey privateKey, Path targetPath);
}
