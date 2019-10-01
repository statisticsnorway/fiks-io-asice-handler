package no.ks.fiks.io.asice.model;

import java.io.InputStream;

public interface Content {
    String getFilnavn();
    InputStream getPayload();
}
