package no.ks.fiks.io.asice.write;

import com.google.common.base.Preconditions;
import lombok.NonNull;
import no.difi.asic.AsicWriter;
import no.difi.asic.AsicWriterFactory;
import no.difi.asic.SignatureMethod;
import no.ks.fiks.io.asice.crypto.PipedEncryptionService;
import no.ks.fiks.io.asice.model.Content;
import no.ks.fiks.io.asice.sign.SignatureHelperProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.*;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;

import static com.google.common.io.Closeables.closeQuietly;

public class EncryptedAsicWriterImpl implements EncryptedAsicWriter {

    private static final Logger log = LoggerFactory.getLogger(EncryptedAsicWriterImpl.class);
    private final PipedEncryptionService pipedEncryptionService;
    private final ExecutorService executor;
    private final AsicWriterFactory asicWriterFactory = AsicWriterFactory.newFactory(SignatureMethod.CAdES);
    private final SignatureHelperProvider signatureHelperProvider;

    public EncryptedAsicWriterImpl(PipedEncryptionService pipedEncryptionService,
                                   ExecutorService executor,
                                   SignatureHelperProvider signatureHelperProvider) {
        Preconditions.checkNotNull(pipedEncryptionService);
        Preconditions.checkNotNull(executor);
        Preconditions.checkNotNull(signatureHelperProvider);
        this.pipedEncryptionService = pipedEncryptionService;
        this.executor = executor;
        this.signatureHelperProvider = signatureHelperProvider;
    }

    @Override
    public InputStream createAndEncrypt(X509Certificate x509Certificate, List<Content> contents) {
        Preconditions.checkNotNull(x509Certificate);
        Preconditions.checkNotNull(contents);
        try {
            if (contents.isEmpty())
                throw new RuntimeException("Ingen payloads oppgitt, kan ikke kryptere melding");

            PipedInputStream asicInputStream = new PipedInputStream();
            final OutputStream asicOutputStream = new PipedOutputStream(asicInputStream);
            final Map<String, String> mdc = MDC.getCopyOfContextMap();
            executor.execute(() -> {
                try {
                    Optional.ofNullable(mdc).ifPresent(m -> MDC.setContextMap(m));
                    AsicWriter writer = asicWriterFactory.newContainer(asicOutputStream);
                    contents.forEach(p -> write(writer, p));
                    writer.setRootEntryName(contents.get(0)
                        .getFilnavn());
                    writer.sign(
                        signatureHelperProvider.provideSignatureHelper());
                } catch (Exception e) {
                    log.error("Failed to sign stream", e);
                    throw new RuntimeException(e);
                } finally {
                    MDC.clear();
                }
            });


            return pipedEncryptionService.encrypt(asicInputStream, x509Certificate);
        } catch (IOException e) {
            throw new RuntimeException("Feil under bygging av asic", e);
        }
    }

    private void write(@NonNull final AsicWriter writer, @NonNull final Content p) {
        try {
            writer.add(p.getPayload(), p.getFilnavn());
        } catch (IOException e) {
            throw new RuntimeException("Error writing payload to asic", e);
        } finally {
            closeQuietly(p.getPayload());
        }
    }
}
