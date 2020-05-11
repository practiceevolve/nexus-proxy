package com.travelaudience.nexus.proxy;

import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import java.io.IOException;

public class AccessToken {
    private final String rawToken;

    public AccessToken(String token) {
        rawToken = token;
    }

    public String principal() throws IOException {
        JsonWebSignature jws = JsonWebSignature
                .parser(JacksonFactory.getDefaultInstance())
                .setPayloadClass(PayloadWithEmail.class)
                .parse(rawToken);
        return ((PayloadWithEmail) jws.getPayload()).getEmail();
    }
}
