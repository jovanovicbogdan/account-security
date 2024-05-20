package dev.bogdanjovanovic.accountsecurity.totp;

import dev.bogdanjovanovic.accountsecurity.user.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TotpDeviceRepository extends
    JpaRepository<TotpDevice, UUID> {

  Optional<TotpDevice> findByDeviceName(String deviceName);

  Optional<TotpDevice> findByUser(User user);

}
