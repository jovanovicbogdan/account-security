package dev.bogdanjovanovic.accountsecurity.token;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security")
public record TokenProperties(long authTokenExpiration, long refreshTokenExpiration,
                              long preAuthTokenExpiration) {

}
