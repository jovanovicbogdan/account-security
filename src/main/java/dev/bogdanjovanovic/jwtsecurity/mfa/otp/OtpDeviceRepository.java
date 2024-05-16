package dev.bogdanjovanovic.jwtsecurity.mfa.otp;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OtpDeviceRepository extends
    JpaRepository<OtpDevice, UUID> {

}
