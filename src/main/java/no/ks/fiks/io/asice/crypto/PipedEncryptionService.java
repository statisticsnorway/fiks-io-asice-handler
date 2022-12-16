package no.ks.fiks.io.asice.crypto;

import java.io.InputStream;
import java.io.PipedInputStream;
import java.security.cert.X509Certificate;

@FunctionalInterface
public interface PipedEncryptionService {

    PipedInputStream encrypt(final InputStream pipedInputStream, X509Certificate mottakerSertifikat);
}
