package com.app.mentora.controller;

import com.app.mentora.dto.LoginSecurityProperties;
import com.app.mentora.dto.RefreshTokenResponse;
import com.app.mentora.dto.auth.*;
import com.app.mentora.model.auth.User;
import com.app.mentora.model.token.RefreshToken;
import com.app.mentora.repository.auth.UserRepository;
import com.app.mentora.security.JwtUtil;
import com.app.mentora.service.auth.CustomUserDetailsService;
import com.app.mentora.service.limit_rate.RateLimitService;
import com.app.mentora.service.token.RefreshTokenService;
import com.app.mentora.service.token.TokenBlacklistService;
import com.app.mentora.util.IpUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


import java.time.Duration;
import java.time.Instant;
import java.util.*;


/**
 * Authentication Controller:
 * - Handles signup, login, refresh, and logout endpoints.
 * - Uses JWT access tokens and HttpOnly refresh token cookies.
 * - Enforces IP-based rate limits and account lockout.
 */

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String REFRESH_TOKEN_COOKIE = "refreshToken";

    private final AuthenticationManager authManager;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final RefreshTokenService refreshTokenService;
    private final RateLimitService rateLimitService;
    private final TokenBlacklistService blacklistService;
    private final LoginSecurityProperties loginSecurityProperties;

    @Value("${cookie.secure:true}")
    private boolean cookieSecure;

    public AuthController(AuthenticationManager authManager,
                          UserRepository userRepo,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil,
                          CustomUserDetailsService customUserDetailsService,
                          RefreshTokenService refreshTokenService,
                          RateLimitService rateLimitService,
                          TokenBlacklistService blacklistService,
                          LoginSecurityProperties loginSecurityProperties) {
        this.authManager = authManager;
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.customUserDetailsService = customUserDetailsService;
        this.refreshTokenService = refreshTokenService;
        this.rateLimitService = rateLimitService;
        this.blacklistService = blacklistService;
        this.loginSecurityProperties=loginSecurityProperties;
    }



    /** ------------------------- SIGNUP ------------------------- */

    @PostMapping("/signup")
    public ResponseEntity<?> register(@Valid @RequestBody SignupUserDto req, HttpServletRequest request) {
        String clientIP = IpUtils.getClientIP(request);
        log.info("Signup attempt from IP: {}", clientIP);

        // Rate limiting
        if (!rateLimitService.tryConsume(clientIP + ":signup")) {
            log.warn("Rate limit exceeded for signup from IP: {}", clientIP);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Too many requests. Please try again later."));
        }

        // Check if email exists
        Optional<User> existingUser = userRepo.findByEmail(req.getEmail());
        if (existingUser.isPresent()) {
            IpUtils.simulateDelay();
            log.warn("Signup failed: Email already in use from IP: {}", clientIP);


            return ResponseEntity.status(HttpStatus.OK)
                    .body(Map.of("message", "If registration is valid, you will receive confirmation."));

        }



        User u = new User();
        u.setEmail(req.getEmail());
        u.setPassword(passwordEncoder.encode(req.getPassword()));
        u.setRoles(Set.of("ROLE_USER"));
        userRepo.save(u);

        log.info("User registered successfully from IP: {}", clientIP);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully"));
    }

    /** ------------------------- LOGIN ------------------------- */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginUserDto req,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        String clientIP = IpUtils.getClientIP(request);
        log.info("Login attempt from IP: {}", clientIP);

        // Rate limiting by IP
        if (!rateLimitService.tryConsume(clientIP + ":login")) {
            log.warn("Rate limit exceeded for login from IP: {}", clientIP);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Too many login attempts. Please try again later."));
        }

        try {
            User u = customUserDetailsService.getUserByEmail(req.getEmail());
            if (u == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid credentials"));
            }

            // 🔹 Step 2: Check lock status
            if (u.isAccountLocked()) {
                long minutesLeft= customUserDetailsService.handleLock(u);
                if(minutesLeft!=0){
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("error", "Account locked. Try again in " + minutesLeft + " minutes."));
                }

            }

            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
            );

            var userDetails = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
            var roles = userDetails.getAuthorities().stream().map(a -> a.getAuthority()).toList();


            // Generate access token
            String token = jwtUtil.generateToken(userDetails.getUsername(), roles);

            // Get user entity and create refresh token
            User user = customUserDetailsService.getUserByEmail(userDetails.getUsername());


            RefreshTokenResponse refreshTokenResponse = refreshTokenService.createRefreshToken(user,request.getHeader("User-Agent"),request.getRemoteAddr());
            RefreshToken refreshToken=refreshTokenResponse.getRefreshToken();
            String rawToken=refreshTokenResponse.getRawToken();


            // Set refresh token in HttpOnly Secure cookie
            ResponseCookie cookie = buildCookie(rawToken, Duration.ofDays(7));
            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

//            ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, rawToken)
//                    .httpOnly(true)
//                    .secure(cookieSecure)
//                    .path("/api/auth")
//                    .sameSite("Strict")
//                    .maxAge(Duration.ofDays(7))
//                    .build();
//            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

            Map<String, Object> body = Map.of(
                    "token", token,
                    "email", req.getEmail()
            );

            log.info("Login successful from IP: {}", clientIP);
            // Clear rate limit on successful login
            rateLimitService.clearBucket(clientIP + ":login");

            return ResponseEntity.ok(body);

        } catch (BadCredentialsException e) {
            log.error("Login failed from IP: {} - Invalid credentials", clientIP);
            handleFailedAttempt(req.getEmail());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        } catch (LockedException e) {
            log.error("Login failed from IP: {} - Account locked", clientIP);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Account is locked"));
        } catch (DisabledException e) {
            log.error("Login failed from IP: {} - Account disabled", clientIP);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Account is disabled"));
        } catch (Exception e) {
            log.error("Login failed from IP: {} - Unexpected error", clientIP, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Authentication failed"));
        }
    }

    /** ------------------------- REFRESH TOKEN ------------------------- */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@CookieValue(name = REFRESH_TOKEN_COOKIE, required = false) String refreshTokenStr,
                                          HttpServletRequest request,
                                          HttpServletResponse response) {
        String clientIP = IpUtils.getClientIP(request);

        if (refreshTokenStr == null || refreshTokenStr.isEmpty()) {
            log.warn("Refresh token missing from IP: {}", clientIP);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Refresh token is missing"));
        }


        try {
            // Find and verify refresh token
            refreshTokenStr=RefreshToken.hashToken(refreshTokenStr);
            RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenStr)
                    .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

            refreshToken = refreshTokenService.verifyExpiration(refreshToken);
            if (!refreshToken.getIpAddress().equals(request.getRemoteAddr())) {
                // Possible theft or different device
                log.warn("Possible theft or different device: Refresh Token ip address is not the same as the request ip address ");
            }
            User user = refreshToken.getUser();
            if (blacklistService.areAllUserTokensBlacklisted(user.getId())) {
                log.warn("Attempted to refresh token for user with all tokens revoked: {}", user.getEmail());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "All tokens revoked. Please login again."));
            }
            //Limit the refresh tokens per user
            refreshTokenService.LimitRefreshTokenPerUserActive(user.getId());

            List<String> roles = user.getRoles().stream().toList();

            // Generate new access token
            String newAccessToken = jwtUtil.generateToken(user.getEmail(), roles);

            // Rotate refresh token for better security
            RefreshTokenResponse refreshTokenResponse = refreshTokenService.rotateRefreshToken(refreshToken,request.getHeader("User-Agent"),request.getRemoteAddr());
            String rawToken=refreshTokenResponse.getRawToken();
            RefreshToken newRefreshToken =refreshTokenResponse.getRefreshToken();
            // Update cookie with new refresh token
//            ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, rawToken)
//                    .httpOnly(true)
//                    .secure(cookieSecure)
//                    .path("/api/auth")
//                    .sameSite("Strict")
//                    .maxAge(Duration.ofDays(7))
//                    .build();
//            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
            ResponseCookie cookie = buildCookie(rawToken, Duration.ofDays(7));
            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

            log.info("Token refreshed successfully from IP: {}", clientIP);
            return ResponseEntity.ok(Map.of("token", newAccessToken));

        } catch (Exception e) {
            log.error("Token refresh failed from IP: {} - {}", clientIP, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid or expired refresh token"));
        }
    }

    /** ------------------------- LOGOUT ------------------------- */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name = REFRESH_TOKEN_COOKIE, required = false) String refreshTokenStr,
                                    @RequestHeader(value = "Authorization", required = false) String authHeader,
                                    HttpServletRequest request,
                                    HttpServletResponse response) {
        String clientIP = IpUtils.getClientIP(request);

        // Step 1: Blacklist the access token (JWT)
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7);
                String jti = jwtUtil.getJtiFromToken(token);
                var expirationDate = jwtUtil.getExpirationDateFromToken(token);

                blacklistService.blacklistToken(jti, expirationDate);
                log.info("Access token blacklisted on logout from IP: {}", clientIP);
            } catch (Exception e) {
                log.error("Failed to blacklist access token on logout: {}", e.getMessage());
            }
        }

        // Step 2: Revoke refresh token
        if (refreshTokenStr != null && !refreshTokenStr.isEmpty()) {
            refreshTokenService.revokeToken(refreshTokenStr);
            log.info("Refresh token revoked for logout from IP: {}", clientIP);
        }

        // Step 3: Delete refresh token cookie
//        ResponseCookie cookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE, "")
//                .httpOnly(true)
//                .secure(cookieSecure)
//                .path("/api/auth")
//                .maxAge(0)
//                .build();
//        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        ResponseCookie cookie = buildCookie("", Duration.ZERO);
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        log.info("User logged out from IP: {}", clientIP);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
    /** ------------------------- PRIVATE HELPERS ------------------------- */


    // ✅ Centralized cookie creation
    private ResponseCookie buildCookie(String value, Duration age) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE, value)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/api/auth")
                .sameSite("Strict")
                .maxAge(age)
                .build();
    }


    // ⚙️ Increment failed attempts & handle lockout
    private void handleFailedAttempt(String email) {
        User user = customUserDetailsService.getUserByEmail(email);
        if (user == null) return;
        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);
        if (attempts >= loginSecurityProperties.getMaxFailedAttempts()) {
            user.setAccountLocked(true);
            user.setLockTime(Instant.now());
            log.warn("Account locked for user: {}", email);
        }
        customUserDetailsService.save(user);
    }



}