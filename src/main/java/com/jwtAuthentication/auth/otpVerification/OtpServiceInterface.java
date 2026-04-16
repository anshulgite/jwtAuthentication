package com.jwtAuthentication.auth.otpVerification;

public interface OtpServiceInterface {
    
    String generateOtp(String email);
    
    boolean verifyOtp(String email, String otp);
    
    void markOtpAsUsed(String email);
    
    void cleanupExpiredOtps();
    
    boolean isOtpValid(String email);
}
