package dev.bogdanjovanovic.jwtsecurity.user;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, UUID> {

  @Query("SELECT u FROM User u LEFT JOIN FETCH u.tokens WHERE u.username = :username")
  Optional<User> findByUsername(final String username);

}
