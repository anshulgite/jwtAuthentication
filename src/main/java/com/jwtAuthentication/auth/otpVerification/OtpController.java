package com.jwtAuthentication.auth.otpVerification;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/otp")
@RequiredArgsConstructor
public class OtpController {
    
    private final OtpService otpService;
    
    @PostMapping("/generate")
    public ResponseEntity<String> generateOtp(@RequestParam String email) {
        try {
            String otp = otpService.generateOtp(email);
            return ResponseEntity.ok("OTP sent to " + email);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to send OTP: " + e.getMessage());
        }
    }
    
    @PostMapping("/verify")
    public ResponseEntity<String> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        try {
            boolean isValid = otpService.verifyOtp(email, otp);
            if (isValid) {
                return ResponseEntity.ok("OTP verified successfully");
            } else {
                return ResponseEntity.badRequest().body("Invalid or expired OTP");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to verify OTP: " + e.getMessage());
        }
    }
    
    @PostMapping("/validate")
    public ResponseEntity<String> validateOtp(@RequestParam String email) {
        try {
            boolean isValid = otpService.isOtpValid(email);
            if (isValid) {
                return ResponseEntity.ok("Valid OTP exists for this email");
            } else {
                return ResponseEntity.badRequest().body("No valid OTP found for this email");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to validate OTP: " + e.getMessage());
        }
    }
    
    @PostMapping("/mark-used")
    public ResponseEntity<String> markOtpAsUsed(@RequestParam String email) {
        try {
            otpService.markOtpAsUsed(email);
            return ResponseEntity.ok("OTP marked as used");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to mark OTP as used: " + e.getMessage());
        }
    }
}
