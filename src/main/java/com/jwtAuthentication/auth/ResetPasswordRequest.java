package com.jwtAuthentication.auth;

public record ResetPasswordRequest(String username, String otp, String newPassword) {
}
