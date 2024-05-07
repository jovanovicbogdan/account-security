package dev.bogdanjovanovic.jwtsecurity.auth;

import static org.assertj.core.api.Assertions.assertThat;

import dev.bogdanjovanovic.jwtsecurity.AbstractTestcontainers;
import dev.bogdanjovanovic.jwtsecurity.user.User;
import dev.bogdanjovanovic.jwtsecurity.user.User.Role;
import dev.bogdanjovanovic.jwtsecurity.config.RsaKeyProperties;
import dev.bogdanjovanovic.jwtsecurity.user.UserRepository;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

@DataJpaTest
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = Replace.NONE)
@DisplayName("Unit tests for UserRepository")
@Tag("unit")
class UserRepositoryTests extends AbstractTestcontainers {

  @Autowired
  private UserRepository underTest;

  @Autowired
  private ApplicationContext applicationContext;

  @MockBean
  private RsaKeyProperties rsaKeyProperties;

  @BeforeEach
  void beforeEach() {
    underTest.deleteAll();
    System.out.println(applicationContext.getBeanDefinitionCount());
    final User user = new User("Bogdan", "Jovanovic",
        "bogdan@example.com", "bjovanovic",
        "bjovanovic", Role.ADMIN, false, Collections.emptyList());
    underTest.save(user);
  }

  @Test
  void canFindAllUsers() {
    List<User> users = underTest.findAll();
    users.forEach(System.out::println);
    assertThat(users.size()).isEqualTo(1);
  }

}
