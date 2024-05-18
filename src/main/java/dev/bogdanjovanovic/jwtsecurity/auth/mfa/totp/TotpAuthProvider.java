package dev.bogdanjovanovic.jwtsecurity.auth.mfa.totp;

import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.jwtsecurity.user.User;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;

//@Component
public class TotpAuthProvider implements AuthenticationProvider {

  private final UserDetailsService userDetailsService;

  public TotpAuthProvider(final UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  @Override
  public Authentication authenticate(final Authentication authentication)
      throws AuthenticationException {
    final Totp totp = (Totp) authentication;
    final String username = totp.getName();
    final User user = (User) userDetailsService.loadUserByUsername(username);
    if (user.totpDevice() == null) {
      throw new UnauthorizedException("No device attached");
    }
    return totp.getAuthentication();
  }

  @Override
  public boolean supports(final Class<?> authentication) {
    return authentication == Totp.class;
  }
}
