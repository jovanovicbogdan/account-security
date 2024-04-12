package dev.bogdanjovanovic.jwtsecurity;

import dev.bogdanjovanovic.jwtsecurity.auth.User;
import dev.bogdanjovanovic.jwtsecurity.auth.User.Role;
import dev.bogdanjovanovic.jwtsecurity.auth.UserRepository;
import dev.bogdanjovanovic.jwtsecurity.config.RsaKeyProperties;
import dev.bogdanjovanovic.jwtsecurity.token.TokenProperties;
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
      final PasswordEncoder passwordEncoder) {
    return (args) -> {
      final User user = new User(
          "John",
          "Doe",
          "johndoe@example.com",
          "johndoe",
          passwordEncoder.encode("johndoe"),
          Role.ADMIN,
          Collections.emptyList()
      );
      userRepository.save(user);
    };
  }

}
