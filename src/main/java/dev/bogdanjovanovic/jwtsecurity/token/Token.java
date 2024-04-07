package dev.bogdanjovanovic.jwtsecurity.token;

import dev.bogdanjovanovic.jwtsecurity.auth.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;

@Entity
@Table(name = "token")
public class Token {

  @Id
  @GeneratedValue
  private Long tokenId;
  @Column(nullable = false, columnDefinition = "text")
  private String token;
  @Column(nullable = false)
  private TokenType tokenType;
  @Column(nullable = false)
  private boolean isExpired = false;
  @Column(nullable = false)
  private boolean isRevoked = false;
  @ManyToOne
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  public Token() {
  }

  public Token(Long tokenId, String token, TokenType tokenType, boolean isExpired,
      boolean isRevoked, User user) {
    this.tokenId = tokenId;
    this.token = token;
    this.tokenType = tokenType;
    this.isExpired = isExpired;
    this.isRevoked = isRevoked;
    this.user = user;
  }

  public Token(String token, TokenType tokenType, boolean isExpired, boolean isRevoked, User user) {
    this.token = token;
    this.tokenType = tokenType;
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

}
