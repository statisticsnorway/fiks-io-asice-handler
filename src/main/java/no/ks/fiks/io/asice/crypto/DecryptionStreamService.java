package no.ks.fiks.io.asice.crypto;

import java.io.InputStream;
import java.security.PrivateKey;

@FunctionalInterface
public interface DecryptionStreamService {

    InputStream decrypterStream(final InputStream encryptedStream, PrivateKey privateKey);
}
