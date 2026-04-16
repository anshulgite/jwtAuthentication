package com.jwtAuthentication.auth.otpVerification;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table(name = "otp")
public class OtpEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "otp_sequence")
    @SequenceGenerator(name = "otp_sequence", sequenceName = "otp_sequence", allocationSize = 1)
    private Long otpId;
    private String otp;
    private String email;
    private Long userId;
    @Column(name = "created_at",updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;
    private LocalDateTime expiredAt;
    @Column(name = "is_used")
    private Boolean isUsed;
    @Column(name = "is_verified")
    private Boolean isVerified;
    @Column(name = "attempts ")
    private Integer attempts;

    public boolean isExpired() {
        return expiredAt.isBefore(LocalDateTime.now());
    }
    public boolean isValid() {
        return !isExpired() && !isUsed && !isVerified;
    }
}
