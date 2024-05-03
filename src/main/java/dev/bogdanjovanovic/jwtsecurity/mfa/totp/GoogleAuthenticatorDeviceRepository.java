package dev.bogdanjovanovic.jwtsecurity.mfa.totp;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GoogleAuthenticatorDeviceRepository extends
    JpaRepository<GoogleAuthenticatorDevice, UUID> {

}
