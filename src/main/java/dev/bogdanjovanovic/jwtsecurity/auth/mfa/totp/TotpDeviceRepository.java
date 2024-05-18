package dev.bogdanjovanovic.jwtsecurity.auth.mfa.totp;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TotpDeviceRepository extends
    JpaRepository<TotpDevice, UUID> {

}
