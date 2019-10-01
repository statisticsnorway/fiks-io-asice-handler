package no.ks.fiks.io.asice.model;

import lombok.NonNull;

import java.io.InputStream;

public class StreamContent implements Content {
    private InputStream payload;
    private String filnavn;

    public StreamContent(@NonNull InputStream payload, @NonNull String filnavn) {
        this.payload = payload;
        this.filnavn = filnavn;
    }

    @Override
    public String getFilnavn() {
        return filnavn;
    }

    @Override
    public InputStream getPayload() {
        return payload;
    }
}
