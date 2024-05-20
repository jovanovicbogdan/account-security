package dev.bogdanjovanovic.accountsecurity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

public class TestcontainersTest extends AbstractTestcontainers {

  @Test
  void canStartPostgresDb() {
    assertThat(postgreSqlContainer.isRunning()).isTrue();
    assertThat(postgreSqlContainer.isCreated()).isTrue();
  }

}
