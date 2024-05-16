package dev.bogdanjovanovic.jwtsecurity.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security")
public record TokenProperties(long authTokenExpiration, long refreshTokenExpiration,
                              long preAuthTokenExpiration) {

}
