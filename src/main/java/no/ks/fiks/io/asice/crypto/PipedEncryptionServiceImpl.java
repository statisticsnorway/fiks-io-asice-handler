package no.ks.fiks.io.asice.crypto;

import com.google.common.base.Preconditions;
import no.ks.kryptering.CMSKrypteringImpl;
import no.ks.kryptering.CMSStreamKryptering;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;

public class PipedEncryptionServiceImpl implements PipedEncryptionService {

    private static final Logger log = LoggerFactory.getLogger(PipedEncryptionServiceImpl.class);

    private final CMSStreamKryptering cmsKryptoHandler = new CMSKrypteringImpl();
    private final ExecutorService executor;

    public PipedEncryptionServiceImpl(ExecutorService executor) {
        Preconditions.checkNotNull(executor);
        this.executor = executor;
    }

    @Override
    public PipedInputStream encrypt(PipedInputStream pipedInputStream, X509Certificate mottakerSertifikat) {
        Preconditions.checkNotNull(pipedInputStream);
        Preconditions.checkNotNull(mottakerSertifikat);

        final Map<String, String> mdc = MDC.getCopyOfContextMap();
        try {
            final PipedInputStream kryptertInputStream = new PipedInputStream();

            executor.execute(() -> {
                Optional.ofNullable(mdc).ifPresent(MDC::setContextMap);
                try (OutputStream krypteringStream = cmsKryptoHandler.getKrypteringOutputStream(
                    new PipedOutputStream(kryptertInputStream), mottakerSertifikat)) {
                    IOUtils.copy(pipedInputStream, krypteringStream);
                } catch (IOException e) {
                    log.warn("Failed to decrypt stream", e);
                    throw new RuntimeException(e);
                } finally {
                    MDC.clear();
                }
            });

            return kryptertInputStream;
        } catch (Throwable e) {
            log.warn("Feilet under kryptering", e);
            throw new RuntimeException("Kryptering feilet", e);
        }
    }
}
