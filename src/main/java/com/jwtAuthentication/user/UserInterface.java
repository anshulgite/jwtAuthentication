package com.jwtAuthentication.user;

import java.util.List;

public interface UserInterface {

    public UserEntity saveUser(UserEntity user);
    public UserEntity getUser(String username);
    public UserEntity updateUser(UserEntity user);
    public boolean deleteUser(Long userId);
    public UserEntity getUserById(Long id);
    public List<UserEntity> getAllUsers();
    public boolean changePassword(String username, String currentPassword, String newPassword);
    public String forgotPassword(String username);
    public String resetPasswordWithOtp(String username, String otp, String newPassword);
}
