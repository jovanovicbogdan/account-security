package dev.bogdanjovanovic.jwtsecurity.demo;

import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/private/demo")
@CrossOrigin(origins = {"http://localhost:4200"})
public class DemoController {

  @GetMapping
  public ApiResponseWrapper<DemoResponse> privateRoute(@AuthenticationPrincipal final Jwt jwt) {
    return new ApiResponseWrapper<>(new DemoResponse(String.format("Hello, %s!", jwt.getSubject())));
  }

  public record DemoResponse(String message) { }

}
