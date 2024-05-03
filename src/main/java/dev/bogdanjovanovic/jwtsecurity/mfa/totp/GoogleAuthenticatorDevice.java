package dev.bogdanjovanovic.jwtsecurity.mfa.totp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "google_authenticator_device")
public class GoogleAuthenticatorDevice {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID googleAuthenticatorDeviceId;
  @Column(unique = true, nullable = false)
  private String name;
  @Column(nullable = false)
  private String secret;
  @Column(nullable = false)
  private boolean confirmed;
  @Column(nullable = false)
  private boolean enabled;

  public UUID getGoogleAuthenticatorDeviceId() {
    return googleAuthenticatorDeviceId;
  }

  public String getName() {
    return name;
  }

  public String getSecret() {
    return secret;
  }

  public boolean isConfirmed() {
    return confirmed;
  }

  public boolean requiresMfa() {
    return confirmed;
  }

  public boolean isEnabled() {
    return enabled;
  }

}
