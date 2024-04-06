package dev.bogdanjovanovic.jwtsecurity.auth;

import static org.assertj.core.api.Assertions.assertThat;

import dev.bogdanjovanovic.jwtsecurity.AbstractTestcontainers;
import dev.bogdanjovanovic.jwtsecurity.demo.DemoController.DemoResponse;
import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase(replace = Replace.NONE)
@DisplayName("Integration tests for Authentication API endpoints")
@Tag("integration")
@Transactional
public class AuthIntegrationTests extends AbstractTestcontainers {

  @Autowired
  private TestRestTemplate restTemplate;

  @Test
  void whenUnauthenticated_thenShouldReturnUnauthorized() {
    final ResponseEntity<String> response = restTemplate.exchange("/api/v1/demo", HttpMethod.GET,
        null, String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  @Rollback
  void whenAuthenticated_thenShouldReturnOk() {
    final String username = "johndoe";
    final String password = "secretpassword";

    final RegisterRequest registerRequest = new RegisterRequest(
        "John",
        "Doe",
        "johndoe@example.com",
        username,
        password
    );

    final ResponseEntity<Void> registerResponse = restTemplate.exchange(
        "/api/v1/auth/register",
        HttpMethod.POST,
        new HttpEntity<>(registerRequest),
        Void.class
    );
    assertThat(registerResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);

    final LoginRequest loginRequest = new LoginRequest(username, password);

    final ResponseEntity<ApiResponseWrapper<AuthResponse>> loginResponse = restTemplate.exchange(
        "/api/v1/auth/login",
        HttpMethod.POST,
        new HttpEntity<>(loginRequest),
        new ParameterizedTypeReference<>() { }
    );
    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(loginResponse.getBody()).isNotNull();
    assertThat(loginResponse.getBody().getData()).isNotNull();

    final AuthResponse authResponse = loginResponse.getBody().getData();
    final String authToken = authResponse.authToken();

    final HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", "Bearer " + authToken);
    final ResponseEntity<ApiResponseWrapper<DemoResponse>> demoResponse = restTemplate.exchange(
        "/api/v1/demo",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        new ParameterizedTypeReference<>() { }
    );
    assertThat(demoResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

}
