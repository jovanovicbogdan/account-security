package dev.bogdanjovanovic.jwtsecurity.auth;

import dev.bogdanjovanovic.jwtsecurity.token.Token;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "users")
public class User implements UserDetails {

  @Id
  @GeneratedValue
  private Long userId;

  @Column(nullable = false, length = 64)
  private String firstName;
  @Column(nullable = false, length = 64)
  private String lastName;
  @Column(unique = true, nullable = false)
  private String email;
  @Column(unique = true, nullable = false, length = 64)
  private String username;
  @Column(nullable = false)
  private String passwordHash;
  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private Role role;
  @OneToMany(mappedBy = "user")
  private List<Token> tokens;

  public User() {
  }

  public User(Long userId, String firstName, String lastName, String email, String username,
      String passwordHash, Role role, List<Token> tokens) {
    this.userId = userId;
    this.firstName = firstName;
    this.lastName = lastName;
    this.email = email;
    this.username = username;
    this.passwordHash = passwordHash;
    this.role = role;
    this.tokens = tokens;
  }

  public User(String firstName, String lastName, String email, String username, String passwordHash,
      Role role, List<Token> tokens) {
    this.firstName = firstName;
    this.lastName = lastName;
    this.email = email;
    this.username = username;
    this.passwordHash = passwordHash;
    this.role = role;
    this.tokens = tokens;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority(role.name()));
  }

  @Override
  public String getPassword() {
    return passwordHash;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  public Long getUserId() {
    return userId;
  }

  public String getFirstName() {
    return firstName;
  }

  public String getLastName() {
    return lastName;
  }

  public String getEmail() {
    return email;
  }

  public Role getRole() {
    return role;
  }

  public enum Role {
    ADMIN,
    USER
  }

  private User(Builder builder) {
    this.userId = builder.userId;
    this.firstName = builder.firstName;
    this.lastName = builder.lastName;
    this.email = builder.email;
    this.username = builder.username;
    this.passwordHash = builder.passwordHash;
    this.role = builder.role;
    this.tokens = builder.tokens;
  }

  @Override
  public String toString() {
    return "User{" +
        "userId=" + userId +
        ", firstName='" + firstName + '\'' +
        ", lastName='" + lastName + '\'' +
        ", email='" + email + '\'' +
        ", username='" + username + '\'' +
        ", passwordHash='" + passwordHash + '\'' +
        ", role=" + role +
        ", tokens=" + tokens +
        '}';
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private Long userId;
    private String firstName;
    private String lastName;
    private String email;
    private String username;
    private String passwordHash;
    private Role role;
    private List<Token> tokens;

    public Builder userId(Long userId) {
      this.userId = userId;
      return this;
    }

    public Builder firstName(String firstName) {
      this.firstName = firstName;
      return this;
    }

    public Builder lastName(String lastName) {
      this.lastName = lastName;
      return this;
    }

    public Builder email(String email) {
      this.email = email;
      return this;
    }

    public Builder username(String username) {
      this.username = username;
      return this;
    }

    public Builder passwordHash(String passwordHash) {
      this.passwordHash = passwordHash;
      return this;
    }

    public Builder role(Role role) {
      this.role = role;
      return this;
    }

    public Builder tokens(List<Token> tokens) {
      this.tokens = tokens;
      return this;
    }

    public User build() {
      return new User(this);
    }
  }
}
