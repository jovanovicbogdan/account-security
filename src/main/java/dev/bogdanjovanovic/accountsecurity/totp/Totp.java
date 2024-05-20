package dev.bogdanjovanovic.accountsecurity.totp;

import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class Totp implements Authentication {

  public static final String TOTP_HEADER_NAME = "TOTP";
  private final Authentication authentication;
  private final String code;

  public Totp(final Authentication authentication, final String code) {
    this.authentication = authentication;
    this.code = code;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authentication.getAuthorities();
  }

  @Override
  public String getCredentials() {
    return code;
  }

  @Override
  public Object getDetails() {
    return authentication.getDetails();
  }

  @Override
  public Object getPrincipal() {
    return authentication.getPrincipal();
  }

  @Override
  public boolean isAuthenticated() {
    return authentication.isAuthenticated();
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    authentication.setAuthenticated(isAuthenticated);
  }

  @Override
  public String getName() {
    return authentication.getName();
  }

  public Authentication getAuthentication() {
    return authentication;
  }
}
