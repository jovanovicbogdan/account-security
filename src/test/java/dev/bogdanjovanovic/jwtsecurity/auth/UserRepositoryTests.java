package dev.bogdanjovanovic.jwtsecurity.auth;

import static org.assertj.core.api.Assertions.assertThat;

import dev.bogdanjovanovic.jwtsecurity.AbstractTestcontainers;
import dev.bogdanjovanovic.jwtsecurity.auth.User.Role;
import dev.bogdanjovanovic.jwtsecurity.config.RsaKeyProperties;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;

@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
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
        "bjovanovic", Role.ADMIN, Collections.emptyList());
    underTest.save(user);
  }

  @Test
  void canFindAllUsers() {
    List<User> users = underTest.findAll();
    users.forEach(System.out::println);
    assertThat(users.size()).isEqualTo(1);
  }

}
