package dev.bogdanjovanovic.jwtsecurity;

import com.github.javafaker.Faker;
import javax.sql.DataSource;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public abstract class AbstractTestcontainers {

  @Container
  @ServiceConnection
  protected static final PostgreSQLContainer<?> postgreSqlContainer =
      new PostgreSQLContainer<>("postgres:16.2")
          .withDatabaseName("jwt_security_test")
          .withUsername("postgres")
          .withPassword("rootpassword");

  private static DataSource getDataSource() {
    return DataSourceBuilder.create()
        .driverClassName(postgreSqlContainer.getDriverClassName())
        .url(postgreSqlContainer.getJdbcUrl())
        .username(postgreSqlContainer.getUsername())
        .password(postgreSqlContainer.getPassword())
        .build();
  }

  protected static final Faker FAKER = new Faker();

}
