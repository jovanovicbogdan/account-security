package dev.bogdanjovanovic.jwtsecurity.token;

import dev.bogdanjovanovic.jwtsecurity.auth.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "token")
public class Token {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID tokenId;
  @Column(nullable = false, columnDefinition = "text")
  private String token;
  @Column(nullable = false)
  private boolean isExpired = false;
  @Column(nullable = false)
  private boolean isRevoked = false;
  @ManyToOne
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  public Token() {
  }

  public Token(UUID tokenId, String token, boolean isExpired, boolean isRevoked, User user) {
    this.tokenId = tokenId;
    this.token = token;
    this.isExpired = isExpired;
    this.isRevoked = isRevoked;
    this.user = user;
  }

  public Token(String token, boolean isExpired, boolean isRevoked, User user) {
    this.token = token;
    this.isExpired = isExpired;
    this.isRevoked = isRevoked;
    this.user = user;
  }

  public boolean isExpired() {
    return isExpired;
  }

  public boolean isRevoked() {
    return isRevoked;
  }

  public void setExpired(boolean expired) {
    isExpired = expired;
  }

  public void setRevoked(boolean revoked) {
    isRevoked = revoked;
  }

  public User getUser() {
    return user;
  }

  public enum TokenType {
    AUTH,
    REFRESH
  }

}
