package com.jwtAuthentication.auth;

public record ChangePasswordRequest(
        String username,
        String currentPassword,
        String newPassword) {}
