package no.ks.fiks.io.asice.sign;

import no.difi.asic.SignatureHelper;

@FunctionalInterface
public interface SignatureHelperProvider {

    SignatureHelper provideSignatureHelper();
}
