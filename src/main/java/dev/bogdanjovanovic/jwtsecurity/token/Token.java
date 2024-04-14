package dev.bogdanjovanovic.jwtsecurity.token;

import dev.bogdanjovanovic.jwtsecurity.auth.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Transient;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Table(name = "token")
@EntityListeners(AuditingEntityListener.class)
public class Token {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID tokenId;
  @Column(nullable = false, unique = true, columnDefinition = "text")
  private String token;
//  @Column(nullable = false)
//  private boolean isExpired = false;
  @Column(nullable = false)
  private boolean isRevoked = false;
  @ManyToOne
  @JoinColumn(name = "user_id", nullable = false)
  private User user;
  @CreatedDate
  private Instant createdAt;
  @LastModifiedDate
  private Instant updatedAt;
  @Transient
  private TokenType tokenType;

  public Token() {
  }

  public Token(UUID tokenId, String token, boolean isRevoked, User user) {
    this.tokenId = tokenId;
    this.token = token;
    this.isRevoked = isRevoked;
    this.user = user;
  }

  public Token(String token, boolean isRevoked, User user) {
    this.token = token;
    this.isRevoked = isRevoked;
    this.user = user;
  }

  public boolean isRevoked() {
    return isRevoked;
  }

  public void setRevoked(boolean revoked) {
    isRevoked = revoked;
  }

  public String getToken() {
    return token;
  }

  public User getUser() {
    return user;
  }

  public enum TokenType {
    AUTH,
    REFRESH
  }

}
