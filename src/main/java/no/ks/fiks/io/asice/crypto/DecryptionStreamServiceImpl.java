package no.ks.fiks.io.asice.crypto;

import lombok.NonNull;
import no.ks.kryptering.CMSKrypteringImpl;

import java.io.InputStream;
import java.security.PrivateKey;

public class DecryptionStreamServiceImpl implements DecryptionStreamService {

    private final CMSKrypteringImpl cmsKryptering = new CMSKrypteringImpl();

    @Override
    public InputStream decrypterStream(@NonNull InputStream encryptedStream, @NonNull PrivateKey privateKey) {
        return cmsKryptering.dekrypterData(encryptedStream, privateKey);
    }
}
