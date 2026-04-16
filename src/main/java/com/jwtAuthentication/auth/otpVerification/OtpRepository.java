package com.jwtAuthentication.auth.otpVerification;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<OtpEntity, Long> {
    
    Optional<OtpEntity> findByEmailAndIsUsedFalse(String email);
    
    Optional<OtpEntity> findByEmailAndOtpAndIsUsedFalse(String email, String otp);
    
    @Query("SELECT o FROM OtpEntity o WHERE o.email = :email AND o.isUsed = false AND o.expiredAt > :now")
    Optional<OtpEntity> findValidOtpByEmail(@Param("email") String email, @Param("now") LocalDateTime now);
    
    @Query("SELECT o FROM OtpEntity o WHERE o.email = :email AND o.otp = :otp AND o.isUsed = false AND o.expiredAt > :now")
    Optional<OtpEntity> findValidOtpByEmailAndOtp(@Param("email") String email, @Param("otp") String otp, @Param("now") LocalDateTime now);
    
    void deleteByEmail(String email);
}
