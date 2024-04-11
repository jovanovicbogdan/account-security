package dev.bogdanjovanovic.jwtsecurity;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@TestConfiguration
public class TestConfig {

//  @Bean
//  public PasswordEncoder passwordEncoder() {
//    return new BCryptPasswordEncoder();
//  }

  @Bean
  public RestTemplate testRestTemplate(RestTemplateBuilder builder) {
    final HttpClient httpClient = (HttpClient) HttpClients.custom()
        .disableAutomaticRetries()
        .useSystemProperties()
        .build();
    return builder
//        .errorHandler(new RestTemplateResponseErrorHandler())
        .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(httpClient))
        .build();
  }

}
