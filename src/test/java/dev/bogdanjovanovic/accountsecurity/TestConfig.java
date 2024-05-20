package dev.bogdanjovanovic.accountsecurity;

import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@TestConfiguration
public class TestConfig {

  @Bean
  public RestTemplate testRestTemplate(RestTemplateBuilder builder) {
    return builder
        .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(HttpClients.custom()
            .disableAutomaticRetries()
            .useSystemProperties()
            .build()))
        .build();
  }

}
