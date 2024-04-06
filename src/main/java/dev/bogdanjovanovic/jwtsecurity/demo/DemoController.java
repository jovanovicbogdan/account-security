package dev.bogdanjovanovic.jwtsecurity.demo;

import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import java.security.Principal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

  @GetMapping
  public ApiResponseWrapper<DemoResponse> privateRoute(final Principal principal) {
    return new ApiResponseWrapper<>(new DemoResponse("Hello, " + principal.getName()));
  }

  public record DemoResponse(String message) { }

}
