package dev.bogdanjovanovic.accountsecurity.user;

import dev.bogdanjovanovic.accountsecurity.totp.TotpDevice;
import dev.bogdanjovanovic.accountsecurity.token.Token;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Transient;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "users")
@EntityListeners(AuditingEntityListener.class)
public class User implements UserDetails {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID userId;

  @Column(nullable = false)
  private String firstName;
  @Column(nullable = false)
  private String lastName;
  @Column(unique = true, nullable = false)
  private String email;
  @Column(unique = true, nullable = false)
  private String username;
  @Transient
  @Column(nullable = false)
  private String passwordHash;
  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private Role role;
  @Column(nullable = false)
  private boolean requiresMfa = false;
  @OneToMany(mappedBy = "user")
  private List<Token> tokens = new ArrayList<>();
  @OneToOne(mappedBy = "user", fetch = FetchType.LAZY, cascade = {CascadeType.PERSIST,
      CascadeType.MERGE})
  private TotpDevice totpDevice;
  @CreatedDate
  private Instant createdAt;
  @LastModifiedDate
  private Instant updatedAt;

  public User() {
  }

  public User(UUID userId, String firstName, String lastName, String email, String username,
      String passwordHash, Role role, boolean requiresMfa, List<Token> tokens,
      TotpDevice totpDevice) {
    this.userId = userId;
    this.firstName = firstName;
    this.lastName = lastName;
    this.email = email;
    this.username = username;
    this.passwordHash = passwordHash;
    this.role = role;
    this.requiresMfa = requiresMfa;
    this.tokens = tokens;
    this.totpDevice = totpDevice;
  }

  public User(String firstName, String lastName, String email, String username, String passwordHash,
      Role role, boolean requiresMfa, List<Token> tokens, TotpDevice totpDevice) {
    this.firstName = firstName;
    this.lastName = lastName;
    this.email = email;
    this.username = username;
    this.passwordHash = passwordHash;
    this.role = role;
    this.requiresMfa = requiresMfa;
    this.tokens = tokens;
    this.totpDevice = totpDevice;
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

  public UUID getUserId() {
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

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public boolean requiresMfa() {
    return requiresMfa;
  }

  public TotpDevice getTotpDevice() {
    return totpDevice;
  }

  public enum Role {
    ADMIN,
    USER
  }

  private User(final Builder builder) {
    this.firstName = builder.firstName;
    this.lastName = builder.lastName;
    this.email = builder.email;
    this.username = builder.username;
    this.passwordHash = builder.passwordHash;
    this.role = builder.role;
    this.requiresMfa = builder.requiresMfa;
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
        ", requiresMfa=" + requiresMfa +
        ", tokens=" + tokens +
        ", otpDevice=" + totpDevice +
        ", createdAt=" + createdAt +
        ", updatedAt=" + updatedAt +
        '}';
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private String firstName;
    private String lastName;
    private String email;
    private String username;
    private String passwordHash;
    private Role role;
    private boolean requiresMfa;

    public Builder firstName(final String firstName) {
      this.firstName = firstName;
      return this;
    }

    public Builder lastName(final String lastName) {
      this.lastName = lastName;
      return this;
    }

    public Builder email(final String email) {
      this.email = email;
      return this;
    }

    public Builder username(final String username) {
      this.username = username;
      return this;
    }

    public Builder passwordHash(final String passwordHash) {
      this.passwordHash = passwordHash;
      return this;
    }

    public Builder role(final Role role) {
      this.role = role;
      return this;
    }

    public Builder requiresMfa(final boolean requiresMfa) {
      this.requiresMfa = requiresMfa;
      return this;
    }

    public User build() {
      return new User(this);
    }
  }
}
