package dev.bogdanjovanovic.jwtsecurity.user;

import dev.bogdanjovanovic.jwtsecurity.auth.UserRepository;
import dev.bogdanjovanovic.jwtsecurity.exception.ApiResponseWrapper;
import java.util.List;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@CrossOrigin(origins = {"http://localhost:4200"})
public class UserController {

  private final UserRepository userRepository;

  public UserController(final UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @GetMapping
  public ApiResponseWrapper<List<UserResponse>> getUsers() {
    return new ApiResponseWrapper<>(userRepository
        .findAll()
        .stream()
        .map(user -> new UserResponse(
            user.getUserId(),
            user.getFirstName(),
            user.getLastName(),
            user.getEmail(),
            user.getUsername(),
            user.getRole(),
            user.getCreatedAt(),
            user.getUpdatedAt()
        ))
        .toList());
  }
}
