package com.jwtAuthentication.auth;

import com.jwtAuthentication.auth.refreshToken.RefreshToken;
import com.jwtAuthentication.auth.refreshToken.RefreshTokenService;
import com.jwtAuthentication.common.ApiResponse;
import com.jwtAuthentication.user.UserEntity;
import com.jwtAuthentication.user.UserInterface;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public Map<String, String> login(@RequestBody AuthRequest request) {

        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        UserDetails userDetails = (UserDetails) authenticate.getPrincipal();

        assert userDetails != null;
        String role = userDetails.getAuthorities().iterator().next().getAuthority();

        String accessToken = jwtUtil.generateToken(request.getUsername(),role);
        String refreshToken = jwtUtil.generateRefreshToken(request.getUsername(),role);

        RefreshToken rt = new RefreshToken();
        rt.setToken(refreshToken);
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
    public Map<String, String> refresh(@RequestBody Map<String, String> request) {

        String refreshToken = request.get("refreshToken");

        String username = jwtUtil.extractUsername(refreshToken);
        Claims claims = jwtUtil.getClaims(refreshToken);
        String role = claims.get("role", String.class);
        if (jwtUtil.validateRefreshToken(refreshToken)) {

            RefreshToken byToken = refreshTokenService.findByToken(refreshToken).orElseThrow(() -> new RuntimeException("Token not found"));

            String newAccessToken = jwtUtil.generateToken(username,role);
            String newRefreshToken = jwtUtil.generateRefreshToken(username,role);

            byToken.setToken(newRefreshToken);
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
}
