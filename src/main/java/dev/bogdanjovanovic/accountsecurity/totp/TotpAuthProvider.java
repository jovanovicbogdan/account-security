package dev.bogdanjovanovic.accountsecurity.totp;

import dev.bogdanjovanovic.accountsecurity.exception.AuthException;
import dev.bogdanjovanovic.accountsecurity.user.User;
import dev.bogdanjovanovic.accountsecurity.user.UserRepository;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class TotpAuthProvider implements AuthenticationProvider {

  private final UserRepository userRepository;

  public TotpAuthProvider(final UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public Authentication authenticate(final Authentication authentication)
      throws AuthenticationException {
    final Totp totp = (Totp) authentication;
    final String username = totp.getName();
    final User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("Authentication failed"));
    if (!user.requiresMfa()) {
      throw new AuthException("Authentication failed");
    }
    // TODO: use method from MfaService?
    final boolean isSuccessful = isSuccessful(user, totp);
    if (!isSuccessful) {
      throw new AuthException("Authentication failed");
    }
    return totp.getAuthentication();
  }

  private boolean isSuccessful(final User user, final Totp totp) {
    final TotpDevice totpDevice = user.getTotpDevice();
    if (totpDevice == null) {
      throw new AuthException("Authentication failed");
    }
    if (!totpDevice.isConfirmed() || !totpDevice.isEnabled()) {
      throw new AuthException("Authentication failed");
    }
    final TimeProvider timeProvider = new SystemTimeProvider();
    final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    final CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    return verifier.isValidCode(totpDevice.getSecret(), totp.getCredentials());
  }

  @Override
  public boolean supports(final Class<?> authentication) {
    return authentication == Totp.class;
  }
}
