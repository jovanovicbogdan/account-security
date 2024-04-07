package dev.bogdanjovanovic.jwtsecurity;

import dev.bogdanjovanovic.jwtsecurity.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

//  @Bean
//  CommandLineRunner commandLineRunner(final UserRepository userRepository) {
//    return (args) -> {
//      final User user = new User("Bogdan", "Jovanovic", "bogdan@example.com", "bjovanovic",
//          "bjovanovic", Role.ADMIN, Collections.emptyList());
//      userRepository.save(user);
//    };
//  }

}
