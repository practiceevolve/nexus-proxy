package com.travelaudience.nexus.proxy;

import com.google.api.client.json.jackson2.*;
import com.google.api.client.json.webtoken.*;
import java.io.*;

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
