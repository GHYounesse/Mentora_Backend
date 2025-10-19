package com.app.mentora.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.SignatureException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * ✅ JwtUtil
 * Utility class responsible for generating, validating, and parsing JWT access and refresh tokens.
 * Follows HS512 algorithm and supports issuer/audience validation.
 */
@Component
public class JwtUtil {
    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);
    // ============================= Configurable JWT Properties =============================
    @Value("${jwt.access.secret}")
    private String accessSecret;
    @Value("${jwt.access.expiration-ms}")
    private Long accessExpirationMs;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.audience}")
    private String audience;

    @Value("${jwt.refresh.secret}")
    private String refreshSecret;
    @Value("${jwt.refresh.expiration-ms}")
    private Long refreshExpirationMs;

    // ============================= ACCESS TOKEN ===========================================
    /**
     * @return Secret key for signing access tokens (HS512)
     */
    private SecretKey getAccessKey() {
        // Ensure the secret is at least 64 bytes (512 bits) for HS512
        byte[] keyBytes = accessSecret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 64) {
            throw new IllegalArgumentException("JWT secret key must be at least 64 bytes (512 bits) for HS512");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }
    /**
     * Generate access JWT token.
     * @param username the username of the subject
     * @param roles user roles

     */
    public String generateToken(String username, List<String> roles) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessExpirationMs);

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(username)
                .claim("roles", roles)
                .setId(UUID.randomUUID().toString()) // JWT ID for revocation
                .setIssuedAt(now) // Issued at
                .setExpiration(expiryDate) // Expiration
                .setIssuer(issuer) // Issuer claim
                .setAudience(audience) // Audience claim
                .signWith(getAccessKey(), SignatureAlgorithm.HS512)
                .compact();
    }
    // ============================= TOKEN CLAIMS EXTRACTION =============================

    /** Extract username (subject) from token */
    public String getUsernameFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.getSubject();
    }

    /** Extract JTI (unique token identifier) */
    public String getJtiFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.getId();
    }
    /** Extract user roles from token */
    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return (List<String>) claims.get("roles");
    }
    /** Extract expiration timestamp */
    public Date getExpirationDateFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.getExpiration();
    }

    /** Extract issued-at timestamp */
    public Date getIssuedAtFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.getIssuedAt();
    }

    /** Check if token is expired */
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            return claims.getExpiration().before(new Date());
        } catch (JwtValidationException e) {
            return true;
        }
    }



    /**
     * Fully validate the token:
     *  - Signature
     *  - Expiration
     *  - Issuer / Audience claims
     */
    public boolean validateToken(String token, String username) {
        try {
            Claims claims = validateAndParseToken(token);
            String tokenUsername = claims.getSubject();

            return (tokenUsername.equals(username) && !isTokenExpired(token));
        } catch (JwtValidationException e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
    /**
     * Centralized JWT parser and validator.
     * Ensures strong claim verification.
     */
    public Claims validateAndParseToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getAccessKey())
                    .requireIssuer(issuer) // Validate issuer
                    .requireAudience(audience) // Validate audience
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
            throw new JwtValidationException("Invalid token signature", e);
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            throw new JwtValidationException("Malformed token", e);
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
            throw new JwtValidationException("Token expired", e);
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
            throw new JwtValidationException("Unsupported token", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
            throw new JwtValidationException("Token claims empty", e);
        } catch (IncorrectClaimException e) {
            log.error("JWT claim validation failed: {}", e.getMessage());
            throw new JwtValidationException("Invalid token claims (issuer/audience mismatch)", e);
        }
    }


    // ============================= REFRESH TOKEN =========================================
    /** Generate strong key for refresh token */
    private SecretKey getRefreshKey() {
        // Ensure the secret is at least 64 bytes (512 bits) for HS512
        byte[] keyBytes = refreshSecret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 64) {
            throw new IllegalArgumentException("Refresh secret key must be at least 64 bytes (512 bits) for HS512");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }


    /** Create refresh token with longer expiration */
    public String generateRefreshToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + refreshExpirationMs); // 7 days
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(getRefreshKey(),SignatureAlgorithm.HS512)
                .compact();
    }
    /** Validate refresh token */
    public boolean validateRefreshToken(String token) {
        try{
            Jwts.parserBuilder().setSigningKey(getRefreshKey()).build().parseClaimsJws(token);
            return true;
        }catch (Exception e){
            System.out.println("Error in validating Jwt Refresh Token: "+e);
        }
        return false;
    }
    /** Extract username from refresh token */
    public String getUsernameFromRefreshToken(String token) {
        Claims claims=Jwts.parserBuilder().setSigningKey(getRefreshKey()).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    // ============================= EXCEPTION HANDLER =====================================
    public static class JwtValidationException extends RuntimeException {
        public JwtValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

}
