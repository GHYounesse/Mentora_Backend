package com.app.mentora.service.token;

import com.app.mentora.dto.RefreshTokenResponse;
import com.app.mentora.model.auth.User;
import com.app.mentora.model.token.RefreshToken;
import com.app.mentora.repository.token.RefreshTokenRepository;
import com.app.mentora.security.JwtUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@Service
public class RefreshTokenService {

    @Value("${jwt.refresh.expiration-ms}") // 7 days in milliseconds
    private Long refreshTokenDuration;

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtUtil jwtUtil) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
    }

    public RefreshTokenResponse createRefreshToken(User user) {
        // Revoke all existing tokens for this user (optional - for single device login)
        // revokeAllUserTokens(user);

        String t = jwtUtil.generateRefreshToken(user.getEmail());
        Instant expiryDate = Instant.now().plusMillis(refreshTokenDuration);
        String token= RefreshToken.hashToken(t);
        RefreshToken refreshToken = new RefreshToken(token, user, expiryDate);
        return new RefreshTokenResponse(refreshToken, t);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isExpired() || token.isRevoked()) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token is expired or revoked. Please login again.");
        }
        return token;
    }

    @Transactional
    public void revokeToken(String token) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(rt -> {
                    rt.setRevoked(true);
                    refreshTokenRepository.save(rt);
                });
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
    }

    @Transactional
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(Instant.now());
    }

    public RefreshTokenResponse rotateRefreshToken(RefreshToken oldToken) {
        // Revoke old token
        oldToken.setRevoked(true);
        refreshTokenRepository.save(oldToken);

        // Create new token
        return createRefreshToken(oldToken.getUser());
    }
    //Limit to 5 refresh tokens per user
    public void LimitRefreshTokenPerUserActive(Long userId){
        List<RefreshToken> activeTokens = refreshTokenRepository.findByUserIdAndRevokedFalse(userId);
        if (activeTokens.size() >= 5) {
            // Remove oldest
            RefreshToken oldest = Collections.min(activeTokens, Comparator.comparing(RefreshToken::getExpiryDate));
            oldest.setRevoked(true);
            refreshTokenRepository.save(oldest);
        }

    }
}
