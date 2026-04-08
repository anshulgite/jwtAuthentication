package com.jwtAuthentication.auth;

import com.jwtAuthentication.auth.refreshToken.RefreshToken;
import com.jwtAuthentication.auth.refreshToken.RefreshTokenRepository;
import com.jwtAuthentication.common.Encryption;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Date;

@Component
public class JwtUtil {


    private final RefreshTokenRepository refreshTokenRepository;

    @Autowired
    public JwtUtil(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    private SecretKey getKey() {
        final String SECRET = "mySuperSecretKeyThatIsAtLeast32CharactersLong123";
        return Keys.hmacShaKeyFor(SECRET.getBytes());
    }


    public String generateToken(String username,String role,Long userId,String email) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(getKey())
                .claim("role", role)
                .claim("userId", userId)
                .claim("email", email)
                .compact();
    }

    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    public boolean validateToken(String token, String username) {
        try {
            final String extractedUsername = extractUsername(token);
            return (extractedUsername.equals(username) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    public boolean validateRefreshToken(String token) {
        try {
            Claims claims = getClaims(token);

            // 1. type check
            if (!"refresh".equals(claims.get("type"))) {
                return false;
            }

            // 2. DB check
            RefreshToken rt = refreshTokenRepository.findByToken(Encryption.hashToken(token))
                    .orElseThrow(() -> new RuntimeException("Not found"));

            // 3. revoked check
            if (rt.isRevoked()) {
                return false;
            }

            // 4. expiry check
            return !rt.getExpiryDate().isBefore(LocalDateTime.now());

        } catch (Exception e) {
            return false;
        }
    }

    Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String generateRefreshToken(String username,String role) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7)) // 7 days
                .signWith(getKey())
                .claim("type", "refresh")
                .claim("role", role)
                .compact();
    }
}
