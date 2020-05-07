package com.travelaudience.nexus.proxy;

import com.google.api.client.auth.oauth2.*;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.*;
import com.google.api.client.json.jackson2.*;
import static com.travelaudience.nexus.proxy.ContextKeys.HAS_AUTHORIZATION_HEADER;
import static com.travelaudience.nexus.proxy.Paths.ALL_PATHS;
import static com.travelaudience.nexus.proxy.Paths.ROOT_PATH;

import com.google.api.client.util.Base64;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import com.google.common.primitives.Ints;

import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.VirtualHostHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;

import java.io.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * A verticle which implements a simple proxy for authenticating Nexus users against Google Cloud IAM.
 */
public class IamAuthNexusProxyVerticle extends BaseNexusProxyVerticle {
    private static final Logger LOGGER = LoggerFactory.getLogger(IamAuthNexusProxyVerticle.class);

    private static final Integer AUTH_CACHE_TTL = Ints.tryParse(System.getenv("AUTH_CACHE_TTL"));
    private static final String CLIENT_ID = System.getenv("CLIENT_ID");
    private static final String CLIENT_SECRET = System.getenv("CLIENT_SECRET");
    private static final String TOKEN_ENDPOINT = System.getenv("TOKEN_ENDPOINT");
    private static final String AUTHORIZE_ENDPOINT = System.getenv("AUTHORIZE_ENDPOINT");
    private static final String KEYSTORE_PATH = System.getenv("KEYSTORE_PATH");
    private static final String KEYSTORE_PASS = System.getenv("KEYSTORE_PASS");

    private static final String REDIRECT_URL = System.getenv("REDIRECT_URL");
    private static final Integer SESSION_TTL = Ints.tryParse(System.getenv("SESSION_TTL"));

    /**
     * The path that corresponds to the callback URL to be called by Google.
     */
    private static final String CALLBACK_PATH = "/oauth/callback";
    /**
     * The path that corresponds to the URL where users may get their CLI credentials from.
     */
    private static final String CLI_CREDENTIALS_PATH = "/cli/credentials";
    /**
     * The path that corresponds to all possible paths within the Nexus Docker registry.
     */
    private static final String DOCKER_V2_API_PATHS = "/v2/*";
    /**
     * The path that corresponds to all possible paths within the Nexus Maven repositories.
     */
    private static final String NEXUS_REPOSITORY_PATHS = "/repository/*";

    /**
     * The name of the parameters conveying the authorization code when {@code CALLBACK_PATH} is called.
     */
    private static final String AUTH_CODE_PARAM_NAME = "code";

    /**
     * The name of the response header conveying information about the Docker registry's version.
     */
    private static final CharSequence DOCKER_DISTRIBUTION_API_VERSION_NAME =
            HttpHeaders.createOptimized("Docker-Distribution-Api-Version");
    /**
     * The value of the response header conveying information about the Docker registry's version.
     */
    private static final CharSequence DOCKER_DISTRIBUTION_API_VERSION_VALUE =
            HttpHeaders.createOptimized("registry/2.0");
    /**
     * The name of the 'WWW-Authenticate' header.
     */
    private static final CharSequence WWW_AUTHENTICATE_HEADER_NAME =
            HttpHeaders.createOptimized("WWW-Authenticate");
    /**
     * The value of the 'WWW-Authenticate' header.
     */
    private static final CharSequence WWW_AUTHENTICATE_HEADER_VALUE =
            HttpHeaders.createOptimized("Basic Realm=\"nexus-proxy\"");


    private AuthorizationCodeFlow authCodeFlow;
    private JwtAuth jwtAuth;

    @Override
    public void init(final Vertx vertx,
                     final Context context) {
        super.init(vertx, context);

        this.authCodeFlow = new AuthorizationCodeFlow.Builder(
                BearerToken.authorizationHeaderAccessMethod(),
                new NetHttpTransport(),
                new JacksonFactory(),
                new GenericUrl(TOKEN_ENDPOINT),
                new BasicAuthentication(CLIENT_ID, CLIENT_SECRET),
                CLIENT_ID,
                AUTHORIZE_ENDPOINT)
                .build();

        this.jwtAuth = JwtAuth.create(
                vertx,
                KEYSTORE_PATH,
                KEYSTORE_PASS,
                ImmutableList.of(nexusDockerHost, nexusHttpHost)
        );
    }

    @Override
    protected void preconfigureRouting(final Router router) {
        router.route().handler(CookieHandler.create());
        router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)).setSessionTimeout(SESSION_TTL));
    }

    @Override
    protected void configureRouting(Router router) {
        // Enforce authentication for the Docker API.
        router.route(DOCKER_V2_API_PATHS).handler(VirtualHostHandler.create(nexusDockerHost, ctx -> {
            if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                LOGGER.debug("No authorization header found. Denying.");
                ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                ctx.response().putHeader(DOCKER_DISTRIBUTION_API_VERSION_NAME, DOCKER_DISTRIBUTION_API_VERSION_VALUE);
                ctx.fail(401);
            } else {
                LOGGER.debug("Authorization header found.");
                ctx.data().put(HAS_AUTHORIZATION_HEADER, true);
                ctx.next();
            }
        }));

        // Enforce authentication for the Nexus UI and API.
        router.route(NEXUS_REPOSITORY_PATHS).handler(VirtualHostHandler.create(nexusHttpHost, ctx -> {
            if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                LOGGER.debug("No authorization header found. Denying.");
                ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                ctx.fail(401);
            } else {
                LOGGER.debug("Authorization header found.");
                ctx.data().put(HAS_AUTHORIZATION_HEADER, true);
                ctx.next();
            }
        }));

        // Configure the callback used by the OAuth2 consent screen.
        router.route(CALLBACK_PATH).handler(ctx -> {
            String authorizationUri = buildAuthorizationUri();

            if (!ctx.request().params().contains(AUTH_CODE_PARAM_NAME)) {
                LOGGER.debug("No authentication code found. Redirecting to consent screen.");
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, authorizationUri).end();
                return;
            }

            String principal;
            TokenResponse tokenResponse;
            try {
                tokenResponse = exchangeAuthCodeForToken(ctx);
                principal = principalFromTokenResponse(tokenResponse);
                storeCredential(tokenResponse, principal);
                LOGGER.debug("Got access tokenResponse for principal {}.", principal);
            } catch (final UncheckedIOException  ex) {
                LOGGER.error("Couldn't request access tokenResponse from IAM. Redirecting to consent screen.", ex);
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, authorizationUri).end();
                return;
            }

            LOGGER.debug("Redirecting principal {} to {}.", principal, ROOT_PATH);
            ctx.session().put(SessionKeys.USER_ID, principal);
            // TODO: get originally requested route (maybe from context?) and redirect there
            ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, ROOT_PATH).end();
        });

        // Configure token-based authentication for all paths in order to support authentication for CLI tools such as Maven and Docker.
        router.route(ALL_PATHS).handler(ctx -> {
            // Check for the presence of an authorization header so we can validate it.
            // If an authorization header is present, this must be a request from a CLI tool.
            final String authHeader = ctx.request().headers().get(HttpHeaders.AUTHORIZATION);

            // Skip this step if no authorization header has been found.
            if (authHeader == null) {
                ctx.next();
                return;
            }

            // The request carries an authorization header.
            // These headers are expected to be of the form "Basic X" where X is a base64-encoded string that corresponds to either "password" or "username:password".
            // The password is then validated as a JWT token, which should have been obtained previously by the user via a call to CLI_CREDENTIALS_PATH.
            final String[] parts = authHeader.split("\\s+");

            if (parts.length != 2) {
                ctx.next();
                return;
            }
            if (!"Basic".equals(parts[0])) {
                ctx.next();
                return;
            }

            LOGGER.debug("Request carries HTTP Basic authentication. Validating JWT token.");

            final String credentials = new String(Base64.decodeBase64(parts[1]), Charsets.UTF_8);
            final int colonIdx = credentials.indexOf(":");

            final String password;

            if (colonIdx != -1) {
                password = credentials.substring(colonIdx + 1);
            } else {
                password = credentials;
            }

            // Validate the password as a JWT token.
            jwtAuth.validate(password, userId -> {
                if (userId == null) {
                    LOGGER.debug("Got invalid JWT token. Denying.");
                    ctx.response().setStatusCode(403).end();
                } else {
                    LOGGER.debug("Got valid JWT token for principal {}.", userId);
                    ctx.data().put(SessionKeys.USER_ID, userId);
                    ctx.next();
                }
            });
        });

        // Configure routing for all paths.
        router.route(ALL_PATHS).handler(ctx -> {
            // Check whether the user has already been identified.
            // This happens either at the handler for CALLBACK_PATH or at the handler for JWT tokens.
            final String userId = getUserId(ctx);

            // If the user has NOT been identified yet, and the request does not carry an authorization header, redirect the user to the callback.
            if (userId == null) {
                LOGGER.debug("Got no authorization info. Redirecting to {}.", CALLBACK_PATH);
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, CALLBACK_PATH).end();
                return;
            }

            // At this point we've got a valid principal.
            // We should, however, check whether they are (still) a member of the organization (unless this check is explicitly disabled).
            // This is done mostly to prevent long-lived JWT tokens from being used after a user leaves the organization.
            // see original code from travelaudience
            // https://github.com/travelaudience/nexus-proxy/blob/master/src/main/java/com/travelaudience/nexus/proxy/CloudIamAuthNexusProxyVerticle.java
            // if needed, implement this `authorize` method with something other than `return true`
            if (this.authorize(userId, ctx)) {
                ctx.next();
                return;
            }

            LOGGER.debug("{} is not authorized. Denying.", userId);
            ctx.response().setStatusCode(403).end();
        });

        // Configure the path from where a JWT token can be obtained.
        router.get(CLI_CREDENTIALS_PATH).produces(MediaType.JSON_UTF_8.toString()).handler(ctx -> {
            final String userId = ctx.session().get(SessionKeys.USER_ID);

            LOGGER.debug("Generating JWT token for principal {}.", userId);

            final JsonObject body = new JsonObject()
                    .put("username", userId)
                    .put("password", jwtAuth.generate(userId));

            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString()).end(body.encode());
        });
    }

    private boolean authorize(String userId, RoutingContext ctx) {
        return true;
    }

    private void storeCredential(TokenResponse tokenResponse, String principal) {
        try {
            authCodeFlow.createAndStoreCredential(tokenResponse, principal);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private String principalFromTokenResponse(TokenResponse tokenResponse) {
        try {
            return new AccessToken(tokenResponse.getAccessToken()).principal();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private TokenResponse exchangeAuthCodeForToken(RoutingContext ctx) {
        try {
            return authCodeFlow
                    .newTokenRequest(ctx.request().params().get(AUTH_CODE_PARAM_NAME)).setRedirectUri(REDIRECT_URL)
                    .execute();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private String buildAuthorizationUri() {
        return authCodeFlow
                .newAuthorizationUrl()
                .setRedirectUri(REDIRECT_URL)
                .build();
    }


    @Override
    protected String getUserId(final RoutingContext ctx) {
        return Optional.ofNullable(
                (String) ctx.data().get(SessionKeys.USER_ID)
        ).orElse(
                ctx.session().get(SessionKeys.USER_ID)
        );
    }
}
