package dev.bogdanjovanovic.accountsecurity;

import dev.bogdanjovanovic.accountsecurity.config.RsaKeyProperties;
import dev.bogdanjovanovic.accountsecurity.token.TokenProperties;
import dev.bogdanjovanovic.accountsecurity.totp.TotpDevice;
import dev.bogdanjovanovic.accountsecurity.totp.TotpDeviceRepository;
import dev.bogdanjovanovic.accountsecurity.user.User;
import dev.bogdanjovanovic.accountsecurity.user.User.Role;
import dev.bogdanjovanovic.accountsecurity.user.UserRepository;
import java.util.Collections;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableJpaAuditing
@EnableConfigurationProperties({RsaKeyProperties.class, TokenProperties.class})
@SpringBootApplication
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

  @Profile("dev")
  @Bean
  CommandLineRunner commandLineRunner(final UserRepository userRepository,
      final TotpDeviceRepository totpDeviceRepository,
      final PasswordEncoder passwordEncoder) {
    return (args) -> {
      if (userRepository.findAll().isEmpty()) {
        final User user = new User(
            "John",
            "Doe",
            "admin@example.com",
            "admin",
            passwordEncoder.encode("secretpassword"),
            Role.ADMIN,
            true,
            Collections.emptyList(),
            null
        );
        userRepository.save(user);
        if (totpDeviceRepository.findAll().isEmpty()) {
          final TotpDevice totpDevice = new TotpDevice(
              "iphone",
              "SE6DRY4G4WTRHSVXRG6R3VPJ25TAHFRH",
              true,
              true,
              user
          );
          totpDeviceRepository.save(totpDevice);
        }
      }
    };
  }

}
