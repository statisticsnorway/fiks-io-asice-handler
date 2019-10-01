package no.ks.fiks.io.asice.sign;

import com.google.common.base.Preconditions;
import no.difi.asic.SignatureHelper;
import no.ks.fiks.io.asice.model.KeystoreHolder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class SignatureHelperProviderImpl implements SignatureHelperProvider {

    private final KeystoreHolder keystoreHolder;

    public SignatureHelperProviderImpl(KeystoreHolder keystoreHolder) {
        Preconditions.checkNotNull(keystoreHolder);
        this.keystoreHolder = keystoreHolder;
    }

    @Override
    public SignatureHelper provideSignatureHelper() {
        try (InputStream keyStoreStream = new ByteArrayInputStream(keystoreHolder.getKeyStoreBytes())) {
            return new SignatureHelper(keyStoreStream, keystoreHolder.getKeyStorePassword(), keystoreHolder.getKeyAlias(), keystoreHolder.getKeyPassword());

        } catch (IOException e) {
            throw new RuntimeException("Feil ved innlesing av keystore", e);
        }

    }
}
