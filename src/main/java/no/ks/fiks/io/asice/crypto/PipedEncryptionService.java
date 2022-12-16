package no.ks.fiks.io.asice.crypto;

import java.io.PipedInputStream;
import java.security.cert.X509Certificate;

@FunctionalInterface
public interface PipedEncryptionService {

    PipedInputStream encrypt(final PipedInputStream pipedInputStream, X509Certificate mottakerSertifikat);
}
