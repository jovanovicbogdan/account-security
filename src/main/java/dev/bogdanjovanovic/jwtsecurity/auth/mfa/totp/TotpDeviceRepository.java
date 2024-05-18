package dev.bogdanjovanovic.jwtsecurity.auth.mfa.totp;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TotpDeviceRepository extends
    JpaRepository<TotpDevice, UUID> {

  Optional<TotpDevice> findByDeviceName(String deviceName);

}
