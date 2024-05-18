package dev.bogdanjovanovic.jwtsecurity.auth.mfa.totp;

import dev.bogdanjovanovic.jwtsecurity.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "otp_device")
public class TotpDevice {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID otpDeviceId;
  @Column(unique = true, nullable = false)
  private String name;
  @Column(nullable = false)
  private String secret;
  @Column(nullable = false)
  private boolean confirmed = false;
  @Column(nullable = false)
  private boolean enabled;
  @OneToOne
  @JoinColumn(name = "user_id", referencedColumnName = "userId")
  private User user;

  public TotpDevice() {}

  public UUID getOtpDeviceId() {
    return otpDeviceId;
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

  public boolean isEnabled() {
    return enabled;
  }

}
