package dev.bogdanjovanovic.jwtsecurity.mfa.otp;

import dev.bogdanjovanovic.jwtsecurity.exception.UnauthorizedException;
import dev.bogdanjovanovic.jwtsecurity.user.User;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;

//@Component
public class OtpAuthProvider implements AuthenticationProvider {

  private final UserDetailsService userDetailsService;

  public OtpAuthProvider(final UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  @Override
  public Authentication authenticate(final Authentication authentication)
      throws AuthenticationException {
    final Otp otp = (Otp) authentication;
    final String username = otp.getName();
    final User user = (User) userDetailsService.loadUserByUsername(username);
    if (user.otpDevice() == null) {
      throw new UnauthorizedException("No device attached");
    }
    return otp.getAuthentication();
  }

  @Override
  public boolean supports(final Class<?> authentication) {
    return authentication == Otp.class;
  }
}
