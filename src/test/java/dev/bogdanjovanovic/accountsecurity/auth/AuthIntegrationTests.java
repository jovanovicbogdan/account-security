package dev.bogdanjovanovic.accountsecurity.auth;

import static org.assertj.core.api.Assertions.assertThat;

import dev.bogdanjovanovic.accountsecurity.AbstractTestcontainers;
import dev.bogdanjovanovic.accountsecurity.demo.DemoController.DemoResponse;
import dev.bogdanjovanovic.accountsecurity.exception.ApiResponseWrapper;
import dev.bogdanjovanovic.accountsecurity.token.TokenProperties;
import jakarta.servlet.http.Cookie;
import java.util.Arrays;
import java.util.Objects;
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
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = Replace.NONE)
@DisplayName("Integration tests for Authentication API endpoints")
@Tag("integration")
public class AuthIntegrationTests extends AbstractTestcontainers {

  @Autowired
  private TestRestTemplate restTemplate;

  @Autowired
  private TokenProperties tokenProperties;

  @Test
  void whenUnauthenticated_thenShouldReturnUnauthorized() {
    final ResponseEntity<Void> response = restTemplate.exchange("/api/v1/private/demo", HttpMethod.GET,
        null, Void.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void whenAuthenticated_thenShouldReturnOk() {
    final String username = FAKER.name().username();
    final String password = FAKER.internet().password();
    final String email = FAKER.internet().emailAddress();

    final RegisterRequest registerRequest = new RegisterRequest(
        "John",
        "Doe",
        email,
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
        new ParameterizedTypeReference<>() {
        }
    );
    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(loginResponse.getBody()).isNotNull();
    assertThat(loginResponse.getBody().getData()).isNotNull();
    assertThat(loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();

    final AuthResponse authResponse = loginResponse.getBody().getData();
    assertThat(authResponse).isNotNull();
    assertThat(authResponse.username()).isEqualTo(username);
    assertThat(authResponse.email()).isEqualTo(email);

    final String authToken = authResponse.authToken();

    final HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", String.format("Bearer %s", authToken));
    final ResponseEntity<ApiResponseWrapper<DemoResponse>> demoResponse = restTemplate.exchange(
        "/api/v1/private/demo",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        new ParameterizedTypeReference<>() {
        }
    );
    assertThat(demoResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void whenInvalidCredentials_thenShouldReturnUnauthorized() {
    final String username = FAKER.name().username();
    final String password = FAKER.internet().password();
    final String email = FAKER.internet().emailAddress();

    final RegisterRequest registerRequest = new RegisterRequest(
        "John",
        "Doe",
        email,
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
    final LoginRequest loginRequest = new LoginRequest(username, "invalidpassword");

    final ResponseEntity<Void> loginResponse = restTemplate.exchange(
        "/api/v1/auth/login",
        HttpMethod.POST,
        new HttpEntity<>(loginRequest),
        Void.class
    );
    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
  }

  @Test
  void whenUserDoesNotExist_thenShouldReturnUnauthorized() {
    final String username = FAKER.name().username();
    final String password = FAKER.internet().password();

    final LoginRequest loginRequest = new LoginRequest(username, password);

    final ResponseEntity<ApiResponseWrapper<AuthResponse>> loginResponse = restTemplate.exchange(
        "/api/v1/auth/login",
        HttpMethod.POST,
        new HttpEntity<>(loginRequest),
        new ParameterizedTypeReference<>() {
        }
    );
    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
  }

  @Test
  void whenUserExists_thenShouldReturnConflict() {
    final String username = FAKER.name().username();
    final String password = FAKER.internet().password();
    final String email = FAKER.internet().emailAddress();

    final RegisterRequest registerRequest = new RegisterRequest(
        "John",
        "Doe",
        email,
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

    final ResponseEntity<Void> registerResponse2 = restTemplate.exchange(
        "/api/v1/auth/register",
        HttpMethod.POST,
        new HttpEntity<>(registerRequest),
        Void.class
    );
    assertThat(registerResponse2.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
  }

  @Test
  void whenLogout_thenUserShouldBeLoggedOut() {
    final String username = FAKER.name().username();
    final String password = FAKER.internet().password();
    final String email = FAKER.internet().emailAddress();

    final RegisterRequest registerRequest = new RegisterRequest(
        "John",
        "Doe",
        email,
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
        new ParameterizedTypeReference<>() {
        }
    );

    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(loginResponse.getBody()).isNotNull();
    assertThat(loginResponse.getBody().getData()).isNotNull();
    assertThat(loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();

    final Cookie refreshTokenCookie = parseRefreshTokenCookie(loginResponse);

    final AuthResponse authResponse = loginResponse.getBody().getData();
    assertThat(authResponse).isNotNull();
    assertThat(authResponse.username()).isEqualTo(username);
    assertThat(authResponse.email()).isEqualTo(email);

    final HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE,
        String.format("%s=%s", AuthController.REFRESH_TOKEN_COOKIE_NAME, refreshTokenCookie.getValue()));
    final ResponseEntity<Void> logoutResponse = restTemplate.exchange(
        "/api/v1/auth/logout",
        HttpMethod.POST,
        new HttpEntity<>(headers),
        Void.class
    );
    assertThat(logoutResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

    final ResponseEntity<ApiResponseWrapper<AuthResponse>> refreshTokenResponse = restTemplate.exchange(
        "/api/v1/auth/refresh",
        HttpMethod.POST,
        new HttpEntity<>(headers),
        new ParameterizedTypeReference<>() {
        }
    );
    assertThat(refreshTokenResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void whenRefreshToken_thenShouldReturnNewAuthToken() throws InterruptedException {
    final String username = FAKER.name().username();
    final String password = FAKER.internet().password();
    final String email = FAKER.internet().emailAddress();

    final RegisterRequest registerRequest = new RegisterRequest(
        "John",
        "Doe",
        email,
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
        new ParameterizedTypeReference<>() {
        }
    );

    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(loginResponse.getBody()).isNotNull();
    assertThat(loginResponse.getBody().getData()).isNotNull();
    assertThat(loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();

    final Cookie refreshTokenCookie = parseRefreshTokenCookie(loginResponse);

    final AuthUserResponse authResponse = loginResponse.getBody().getData();
    assertThat(authResponse).isNotNull();
    assertThat(authResponse.username()).isEqualTo(username);
    assertThat(authResponse.email()).isEqualTo(email);

    // Sleep for 1 second to ensure the new token is different
    Thread.sleep(1000);

    final HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE,
        String.format("%s=%s", AuthController.REFRESH_TOKEN_COOKIE_NAME, refreshTokenCookie.getValue()));
    final ResponseEntity<ApiResponseWrapper<AuthUserResponse>> refreshTokenResponse = restTemplate.exchange(
        "/api/v1/auth/refresh",
        HttpMethod.POST,
        new HttpEntity<>(headers),
        new ParameterizedTypeReference<>() {
        }
    );
    assertThat(refreshTokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(refreshTokenResponse.getBody()).isNotNull();
    assertThat(refreshTokenResponse.getBody().getData()).isNotNull();
    assertThat(refreshTokenResponse.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();

    final AuthUserResponse refreshedAuthResponse = refreshTokenResponse.getBody().getData();
    assertThat(refreshedAuthResponse).isNotNull();
    assertThat(refreshedAuthResponse.username()).isEqualTo(username);
    assertThat(refreshedAuthResponse.email()).isEqualTo(email);
    assertThat(refreshedAuthResponse.authToken()).isNotEqualTo(authResponse.authToken());
  }

  @Test
  void whenAuthTokenExpired_thenShouldReturnUnauthorized() throws InterruptedException {
    final String username = FAKER.name().username();
    final String password = FAKER.internet().password();
    final String email = FAKER.internet().emailAddress();

    final RegisterRequest registerRequest = new RegisterRequest(
        "John",
        "Doe",
        email,
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

    final ResponseEntity<ApiResponseWrapper<AuthUserResponse>> loginResponse = restTemplate.exchange(
        "/api/v1/auth/login",
        HttpMethod.POST,
        new HttpEntity<>(loginRequest),
        new ParameterizedTypeReference<>() {
        }
    );

    assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(loginResponse.getBody()).isNotNull();
    assertThat(loginResponse.getBody().getData()).isNotNull();
    assertThat(loginResponse.getHeaders().get(HttpHeaders.SET_COOKIE)).isNotNull();

    final AuthUserResponse authResponse = loginResponse.getBody().getData();
    assertThat(authResponse).isNotNull();
    assertThat(authResponse.username()).isEqualTo(username);
    assertThat(authResponse.email()).isEqualTo(email);

    final HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", String.format("Bearer %s", authResponse.authToken()));

    final ResponseEntity<ApiResponseWrapper<DemoResponse>> demoResponse = restTemplate.exchange(
        "/api/v1/private/demo",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        new ParameterizedTypeReference<>() {
        }
    );
    assertThat(demoResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

    Thread.sleep(tokenProperties.authTokenExpiration() + 10L);

    final ResponseEntity<ApiResponseWrapper<DemoResponse>> demoResponse2 = restTemplate.exchange(
        "/api/v1/private/demo",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        new ParameterizedTypeReference<>() {
        }
    );
    assertThat(demoResponse2.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  private Cookie parseRefreshTokenCookie(final ResponseEntity<?> response) {
    return Arrays.stream(Objects.requireNonNull(
            response.getHeaders().get(HttpHeaders.SET_COOKIE)).toArray())
        .map(Object::toString)
        .filter(header -> header.startsWith(AuthController.REFRESH_TOKEN_COOKIE_NAME))
        .map(header -> {
          final String[] parts = header.split(";");
          final String[] cookieParts = parts[0].split("=");
          return new Cookie(cookieParts[0], cookieParts[1]);
        })
        .findFirst()
        .orElseThrow();
  }
}
