package dev.bogdanjovanovic.jwtsecurity.exception;

import org.springframework.security.core.AuthenticationException;

public class AuthException extends AuthenticationException {

  public AuthException(final String msg, final Throwable cause) {
    super(msg, cause);
  }

  public AuthException(final String msg) {
    super(msg);
  }
}
