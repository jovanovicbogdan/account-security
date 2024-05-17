package dev.bogdanjovanovic.jwtsecurity.auth.mfa.otp;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class OtpConverter implements AuthenticationConverter {

  private final Authentication authentication;

  public OtpConverter(final Authentication authentication) {
    this.authentication = authentication;
  }

  @Override
  public Otp convert(final HttpServletRequest request) {
    final String otpHeaderValue = request.getHeader("otp");

    if (otpHeaderValue == null || otpHeaderValue.isBlank()) {
      return null;
    }

    return new Otp(authentication, otpHeaderValue);
  }
}
