package com.travelaudience.nexus.proxy;

import com.auth0.jwk.*;
import com.fasterxml.jackson.databind.*;
import static com.google.common.base.Preconditions.*;
import static com.google.common.base.Strings.*;
import com.google.common.collect.*;
import java.io.*;
import java.net.*;
import java.util.*;

public class KeycloakJwkProvider implements JwkProvider {

    final URL url;
    private final Integer connectTimeout;
    private final Integer readTimeout;

    private final ObjectReader reader;

    /**
     * Creates a provider that loads from the given URL
     *
     * @param url to load the jwks
     */
    public KeycloakJwkProvider(URL url) {
        this(url, null, null);
    }

    /**
     * Creates a provider that loads from the given URL
     *
     * @param url            to load the jwks
     * @param connectTimeout connection timeout in milliseconds (null for default)
     * @param readTimeout    read timeout in milliseconds (null for default)
     */
    public KeycloakJwkProvider(URL url, Integer connectTimeout, Integer readTimeout) {
        checkArgument(url != null, "A non-null url is required");
        checkArgument(connectTimeout == null || connectTimeout >= 0, "Invalid connect timeout value '" + connectTimeout + "'. Must be a non-negative integer.");
        checkArgument(readTimeout == null || readTimeout >= 0, "Invalid read timeout value '" + readTimeout + "'. Must be a non-negative integer.");

        this.url = url;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;

        this.reader = new ObjectMapper().readerFor(Map.class);
    }

    /**
     * Creates a provider that loads from the given domain's well-known directory.
     * <br><br> It can be a url link 'https://samples.auth0.com' or just a domain 'samples.auth0.com'.
     * If the protocol (http or https) is not provided then https is used by default.
     * The default jwks path "/.well-known/jwks.json" is appended to the given string domain.
     * If the domain url contains a path, e.g. 'https://auth.example.com/some-resource', the path is preserved and the
     * default jwks path is appended.
     * <br><br> For example, when the domain is "samples.auth0.com"
     * the jwks url that will be used is "https://samples.auth0.com/.well-known/jwks.json"
     * If the domain string is "https://auth.example.com/some-resource", the jwks url that will be used is
     * "https://auth.example.com/some-resource/.well-known/jwks.json"
     * <br><br> Use {@link #KeycloakJwkProvider(URL)} if you need to pass a full URL.
     *
     * @param domain where jwks is published
     */
    public KeycloakJwkProvider(String domain) {
        this(urlForDomain(domain));
    }

    static URL urlForDomain(String domain) {
        checkArgument(!isNullOrEmpty(domain), "A domain is required");

        if (!domain.startsWith("http")) {
            domain = "https://" + domain;
        }

        try {
            final URI uri = new URI(domain).normalize();
            return uri.toURL();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new IllegalArgumentException("Invalid jwks uri", e);
        }
    }

    private Map<String, Object> getJwks() throws SigningKeyNotFoundException {
        try {
            final URLConnection c = this.url.openConnection();
            if (connectTimeout != null) {
                c.setConnectTimeout(connectTimeout);
            }
            if (readTimeout != null) {
                c.setReadTimeout(readTimeout);
            }
            c.setRequestProperty("Accept", "application/json");

            try (InputStream inputStream = c.getInputStream()) {
                return reader.readValue(inputStream);
            }
        } catch (IOException e) {
            throw new SigningKeyNotFoundException("Cannot obtain jwks from url " + url.toString(), e);
        }
    }

    public List<Jwk> getAll() throws SigningKeyNotFoundException {
        List<Jwk> jwks = Lists.newArrayList();
        @SuppressWarnings("unchecked") final List<Map<String, Object>> keys = (List<Map<String, Object>>) getJwks().get("keys");

        if (keys == null || keys.isEmpty()) {
            throw new SigningKeyNotFoundException("No keys found in " + url.toString(), null);
        }

        try {
            for (Map<String, Object> values : keys) {
                jwks.add(Jwk.fromValues(values));
            }
        } catch (IllegalArgumentException e) {
            throw new SigningKeyNotFoundException("Failed to parse jwk from json", e);
        }
        return jwks;
    }

    @Override
    public Jwk get(String keyId) throws JwkException {
        final List<Jwk> jwks = getAll();
        if (keyId == null && jwks.size() == 1) {
            return jwks.get(0);
        }
        if (keyId != null) {
            for (Jwk jwk : jwks) {
                if (keyId.equals(jwk.getId())) {
                    return jwk;
                }
            }
        }
        throw new SigningKeyNotFoundException("No key found in " + url.toString() + " with kid " + keyId, null);
    }
}

