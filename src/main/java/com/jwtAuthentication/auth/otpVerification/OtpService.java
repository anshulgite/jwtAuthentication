package com.jwtAuthentication.auth.otpVerification;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class OtpService implements OtpServiceInterface {
    
    private final OtpRepository otpRepository;
    private final JavaMailSender mailSender;
    
    @Override
    @Transactional
    public String generateOtp(String email) {
        String otp = String.format("%06d", new Random().nextInt(1000000));
        
        otpRepository.deleteByEmail(email);
        
        OtpEntity otpEntity = new OtpEntity();
        otpEntity.setOtp(otp);
        otpEntity.setEmail(email);
        otpEntity.setCreatedAt(LocalDateTime.now());
        otpEntity.setExpiredAt(LocalDateTime.now().plusMinutes(5));
        otpEntity.setIsUsed(false);
        otpEntity.setIsVerified(false);
        otpEntity.setAttempts(0);
        
        otpRepository.save(otpEntity);
        
        sendOtpEmail(email, otp);
        
        return otp;
    }
    
    @Override
    @Transactional
    public boolean verifyOtp(String email, String otp) {
        return otpRepository.findValidOtpByEmailAndOtp(email, otp, LocalDateTime.now())
                .map(otpEntity -> {
                    otpEntity.setAttempts(otpEntity.getAttempts() + 1);
                    if (otpEntity.getAttempts() >= 3) {
                        otpEntity.setIsUsed(true);
                        otpRepository.save(otpEntity);
                        return false;
                    }
                    otpEntity.setIsVerified(true);
                    otpRepository.save(otpEntity);
                    return true;
                })
                .orElse(false);
    }
    
    @Override
    @Transactional
    public void markOtpAsUsed(String email) {
        otpRepository.findByEmailAndIsUsedFalse(email)
                .ifPresent(otpEntity -> {
                    otpEntity.setIsUsed(true);
                    otpRepository.save(otpEntity);
                });
    }
    
    @Override
    @Scheduled(fixedRate = 300000)
    @Transactional
    public void cleanupExpiredOtps() {
        otpRepository.findAll().forEach(otpEntity -> {
            if (otpEntity.isExpired()) {
                otpRepository.delete(otpEntity);
            }
        });
    }
    
    @Override
    public boolean isOtpValid(String email) {
        return otpRepository.findValidOtpByEmail(email, LocalDateTime.now()).isPresent();
    }
    
    private void sendOtpEmail(String email, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your OTP Code");
        message.setText("Your OTP code is: " + otp + "\nThis code will expire in 5 minutes.");
        
        mailSender.send(message);
    }
}
