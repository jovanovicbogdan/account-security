package dev.bogdanjovanovic.jwtsecurity.token;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TokenRepository extends JpaRepository<Token, Long> {

  @Query("""
      select t
      from Token t
      inner join User u on t.user.userId = u.userId
      where u.userId = :userId and (t.isExpired = false or t.isRevoked = false)
        """)
  List<Token> findAllValidTokensByUserId(final UUID userId);

  Optional<Token> findByToken(final String token);

}
