package com.jwtAuthentication.auth;

import com.jwtAuthentication.auth.refreshToken.CustomeUserDetails;
import com.jwtAuthentication.auth.refreshToken.RefreshToken;
import com.jwtAuthentication.auth.refreshToken.RefreshTokenService;
import com.jwtAuthentication.common.ApiResponse;
import com.jwtAuthentication.common.Encryption;
import com.jwtAuthentication.user.UserEntity;
import com.jwtAuthentication.user.UserInterface;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final JwtUtil jwtUtil;

    private final RefreshTokenService refreshTokenService;

    private final UserInterface userService;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil,RefreshTokenService refreshTokenService,UserInterface userService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService=refreshTokenService;
        this.userService = userService;
    }


    @PostMapping("/register")
    public ApiResponse<UserEntity> saveUser(@RequestBody UserEntity user) {
        try {
            UserEntity userEntity = userService.saveUser(user);
            return ApiResponse.success(userEntity, "User saved successfully");
        }catch (Exception e)
        {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody AuthRequest request) throws NoSuchAlgorithmException {

        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

       CustomeUserDetails userDetails = (CustomeUserDetails) authenticate.getPrincipal();

        assert userDetails != null;
        String role = userDetails.getAuthorities().iterator().next().getAuthority();
        Long userId = userDetails.getUserId();
        String email = userDetails.getEmail();

        String accessToken = jwtUtil.generateToken(request.getUsername(),role,userId,email);
        String refreshToken = jwtUtil.generateRefreshToken(request.getUsername(),role);

        RefreshToken rt = new RefreshToken();
        rt.setToken(Encryption.hashToken(refreshToken));
        rt.setUsername(request.getUsername());
        rt.setExpiryDate(LocalDateTime.now().plusDays(7));
        rt.setRevoked(false);
        refreshTokenService.save(rt);

        Map<String, String> response = new HashMap<>();
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);


        return response;
    }

    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestBody Map<String, String> request) throws NoSuchAlgorithmException {

        String refreshToken = request.get("refreshToken");

        String username = jwtUtil.extractUsername(refreshToken);
        Claims claims = jwtUtil.getClaims(refreshToken);
        String role = claims.get("role", String.class);
        String email = claims.get("email", String.class);
        Long userId = claims.get("userId", Long.class);
        if (jwtUtil.validateRefreshToken(refreshToken)) {

            RefreshToken byToken = refreshTokenService.findByToken(Encryption.hashToken(refreshToken)).orElseThrow(() -> new RuntimeException("Token not found"));

            String newAccessToken = jwtUtil.generateToken(username,role,userId,email);
            String newRefreshToken = jwtUtil.generateRefreshToken(username,role);

            byToken.setToken(Encryption.hashToken(newRefreshToken));
            refreshTokenService.save(byToken);

            Map<String, String> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            response.put("refreshToken", newRefreshToken);

            return response;
        }

        throw new RuntimeException("Invalid Refresh Token");
    }

    @PostMapping("/logout")
    public String logout(@RequestBody Map<String, String> request) {

        String refreshToken = request.get("refreshToken");
        if(jwtUtil.validateRefreshToken(refreshToken)) {
            RefreshToken rt = refreshTokenService.findByToken(refreshToken)
                    .orElseThrow(() -> new RuntimeException("Token not found"));

            rt.setRevoked(true);
            refreshTokenService.save(rt);
        }
        return "Logged out successfully";
    }

   @PostMapping("/logoutAll")
    public String logoutAll(@RequestBody Map<String, String> request) {

       String refreshToken = request.get("refreshToken");
       if(jwtUtil.validateRefreshToken(refreshToken)) {
           RefreshToken rt = refreshTokenService.findByToken(refreshToken)
                   .orElseThrow(() -> new RuntimeException("Token not found"));

           String username = jwtUtil.extractUsername(refreshToken);
           List<RefreshToken> byUsername = refreshTokenService.findByUsername(username);
           byUsername.forEach(token -> token.setRevoked(true));
           refreshTokenService.saveAll(byUsername);

       }
       return "Logged out successfully";
   }

   @PostMapping("/changePassword")
   public ApiResponse<UserEntity> changePassword(@RequestBody ChangePasswordRequest request) {
        try {
            String username = request.username();
            String currentPassword = request.currentPassword();
            String newPassword = request.newPassword();
            
            if (username == null || currentPassword == null || newPassword == null) {
                return ApiResponse.error("Username, current password, and new password are required", HttpStatus.BAD_REQUEST);
            }
            
            if (newPassword.length() < 6) {
                return ApiResponse.error("New password must be at least 6 characters long", HttpStatus.BAD_REQUEST);
            }
            
            boolean success = userService.changePassword(username, currentPassword, newPassword);
            if (success) {
                UserEntity updatedUser = userService.getUser(username);
                return ApiResponse.success(updatedUser, "Password changed successfully");
            } else {
                return ApiResponse.error("Failed to change password", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
   }

   @PostMapping("/forgotPassword")
   public ApiResponse<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {
            String username = request.username();
            if (username == null || username.trim().isEmpty()) {
                return ApiResponse.error("Username is required", HttpStatus.BAD_REQUEST);
            }
            
            String result = userService.forgotPassword(username);
            return ApiResponse.success(result, "OTP sent successfully");
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
   }

   @PostMapping("/resetPassword")
   public ApiResponse<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        try {
            String username = request.username();
            String otp = request.otp();
            String newPassword = request.newPassword();
            
            if (username == null || otp == null || newPassword == null) {
                return ApiResponse.error("Username, OTP, and new password are required", HttpStatus.BAD_REQUEST);
            }
            
            String result = userService.resetPasswordWithOtp(username, otp, newPassword);
            return ApiResponse.success(result, "Password reset successfully");
        } catch (Exception e) {
            return ApiResponse.error(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
   }
}
