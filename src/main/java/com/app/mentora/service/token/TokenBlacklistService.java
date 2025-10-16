package com.app.mentora.service.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Date;
import java.util.concurrent.TimeUnit;
@Service
public class TokenBlacklistService {
    private static final Logger log = LoggerFactory.getLogger(TokenBlacklistService.class);
    private static final String BLACKLIST_PREFIX = "blacklist:token:";

    private final RedisTemplate<String, String> redisTemplate;

    public TokenBlacklistService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    //Blacklisting a token
    public void blacklistToken(String jti, Date expirationDate) {
        try {
            String key = BLACKLIST_PREFIX + jti;
            long ttl = expirationDate.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                // Store in Redis with TTL matching token expiration
                redisTemplate.opsForValue().set(key, "revoked", ttl, TimeUnit.MILLISECONDS);
                log.info("Token blacklisted successfully: {}", jti);
            } else {
                log.warn("Attempted to blacklist expired token: {}", jti);
            }
        } catch (Exception e) {
            log.error("Failed to blacklist token: {}", jti, e);
            throw new RuntimeException("Failed to blacklist token", e);
        }
    }
    //Check if a token is blacklisted
    public boolean isBlacklisted(String jti) {
        try {
            String key = BLACKLIST_PREFIX + jti;
            Boolean exists = redisTemplate.hasKey(key);
            return exists != null && exists;
        } catch (Exception e) {
            log.error("Failed to check blacklist status for token: {}", jti, e);
            // Fail secure: if we can't check, assume it's blacklisted
            return true;
        }
    }
    //remove a token from the Blacklist
    public void removeFromBlacklist(String jti) {
        try {
            String key = BLACKLIST_PREFIX + jti;
            redisTemplate.delete(key);
            log.info("Token removed from blacklist: {}", jti);
        } catch (Exception e) {
            log.error("Failed to remove token from blacklist: {}", jti, e);
        }
    }
    //blacklisting all the tokens of a user
    public void blacklistAllUserTokens(Long userId) {
        try {
            String pattern = BLACKLIST_PREFIX + "user:" + userId + ":*";
            // In production, you'd maintain a separate set of active tokens per user
            // For now, we'll use a simple marker
            String key = "blacklist:user:" + userId + ":all";
            redisTemplate.opsForValue().set(key, "all-revoked", Duration.ofDays(7));
            log.info("All tokens blacklisted for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to blacklist all user tokens: {}", userId, e);
            throw new RuntimeException("Failed to blacklist user tokens", e);
        }
    }
    //check if all the tokens of a user are blacklisted
    public boolean areAllUserTokensBlacklisted(Long userId) {
        try {
            String key = "blacklist:user:" + userId + ":all";
            Boolean exists = redisTemplate.hasKey(key);
            return exists != null && exists;
        } catch (Exception e) {
            log.error("Failed to check user blacklist status: {}", userId, e);
            return true; // Fail secure
        }
    }
}
