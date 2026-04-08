package com.jwtAuthentication.auth.refreshToken;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    //save
    public RefreshToken save(RefreshToken refreshToken) {
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public List<RefreshToken> findByUsername(String username) {
        return refreshTokenRepository.findByUsername(username);
    }

    public List<RefreshToken> saveAll(List<RefreshToken> byUsername) {
    return refreshTokenRepository.saveAll(byUsername);
    }
}
