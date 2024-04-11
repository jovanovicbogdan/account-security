package dev.bogdanjovanovic.jwtsecurity;

import dev.bogdanjovanovic.jwtsecurity.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
@EnableJpaAuditing
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

//  @Bean
//  CommandLineRunner commandLineRunner(final UserRepository userRepository,
//      final PasswordEncoder passwordEncoder) {
//    return (args) -> {
//      final User user = new User(
//          "John",
//          "Doe",
//          "johndoe@example.com",
//          "johndoe",
//          passwordEncoder.encode("johndoe"),
//          Role.ADMIN,
//          Collections.emptyList()
//      );
//      userRepository.save(user);
//    };
//  }

}
