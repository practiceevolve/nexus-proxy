# -- build
FROM gradle:jdk8 AS builder
COPY ./ /src/
WORKDIR /src/
RUN gradle --debug --no-daemon shadowJar

# -- run
FROM openjdk:8-jre-alpine

ENV BIND_PORT "80"
ENV CLIENT_ID "REPLACE_ME"
ENV CLIENT_SECRET "REPLACE_ME"
ENV CLOUD_IAM_AUTH_ENABLED "true"
ENV NEXUS_HTTP_HOST "nexus.example.com"
ENV REDIRECT_URL "<oauth-callback>"
ENV SESSION_TTL "1440000"
ENV UPSTREAM_HOST "localhost"
ENV UPSTREAM_HTTP_PORT "8081"
ENV JWK_URL "<openid-certs>"
ENV TOKEN_ENDPOINT "<openid-token-endpoint>"
ENV AUTHORIZE_ENDPOINT "<openid-authorize-url>"

COPY --from=builder /src/build/libs/nexus-proxy-2.3.0.jar /nexus-proxy.jar

EXPOSE 8080
EXPOSE 8443

CMD ["-jar", "/nexus-proxy.jar"]

ENTRYPOINT ["java"]
