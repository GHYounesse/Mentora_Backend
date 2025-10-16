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

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);


    private final AuthenticationManager authManager;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    private final RefreshTokenService refreshTokenService;
    private final RateLimitService rateLimitService;
    //private final PasswordValidator passwordValidator;

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
    //private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    /*
    curl --location 'http://localhost:8080/api/auth/signup' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "email":"xxxxx@gmail.com",
        "password":"XXXXXX"
    }'
    Response
    {
    "message": "User registered successfully"
    }
     */
    @PostMapping("/signup")
    public ResponseEntity<?> register(@Valid @RequestBody SignupUserDto req, HttpServletRequest request) {
        String clientIP = getClientIP(request);
        log.info("Signup attempt from IP: {}", clientIP);

        // Rate limiting
        if (!rateLimitService.tryConsume(clientIP + ":signup")) {
            log.warn("Rate limit exceeded for signup from IP: {}", clientIP);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Too many requests. Please try again later."));
        }

        // Check if email exists (but don't reveal it in response)
        if (userRepo.existsByEmail(req.getEmail())) {
            log.warn("Signup failed: Email already in use from IP: {}", clientIP);
            // Generic message to prevent user enumeration
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                    .body(Map.of("error", "Registration failed. Please check your details."));
            try { Thread.sleep(100 + (long)(Math.random() * 100)); } catch (InterruptedException ignored) {}
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("message", "User registered successfully"));
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

    /*
    curl --location 'http://localhost:8080/api/auth/login' \
    --header 'Content-Type: application/json' \
    --header 'Cookie: refreshToken=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ5b3VuZXNzZWdhbWVzQGdtYWlsLmNvbSIsImlhdCI6MTc2MDQ1NTk4MywiZXhwIjoxNzYxMDYwNzgzfQ.Lik_LwBrMoOmZMj66zLbmq8EQwb4H3-PkIoCXO9dxVkvzF5fFMwPaDjupS97FaXXv_dBiiorBzM0vZczcxDe4A' \
    --data-raw '{
        "email":"XXXXX@gmail.com",
        "password":"XXXXX"
    }'
    Response
    {
    "email": "XXXXX@gmail.com",
    "token": "XXXXX"
    }
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginUserDto req,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        String clientIP = getClientIP(request);

//        if (failedAttempts.getOrDefault(req.getEmail(), 0) >= 5) {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN)
//                    .body(Map.of("error", "Account temporarily locked"));
//        }
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
                long lockDuration = loginSecurityProperties.getLockTimeDuration();
                long lockTimeElapsed = Duration.between(u.getLockTime(), Instant.now()).toMillis();

                if (lockTimeElapsed >= lockDuration) {
                    // Unlock account after lock duration expires
                    u.setAccountLocked(false);
                    u.setFailedAttempts(0);
                    u.setLockTime(null);
                    customUserDetailsService.save(u);
                    log.info("Account unlocked automatically for user: {}", u.getEmail());
                } else {
                    long minutesLeft = (lockDuration - lockTimeElapsed) / 60000;
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("error", "Account locked. Try again in " + minutesLeft + " minutes."));
                }
            }

            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
            );

            var userDetails = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
            var roles = userDetails.getAuthorities().stream().map(a -> a.getAuthority()).toList();

            String jti = UUID.randomUUID().toString();
            // Generate access token
            String token = jwtUtil.generateToken(userDetails.getUsername(), roles,jti);

            // Get user entity and create refresh token
            User user = customUserDetailsService.getUserByEmail(userDetails.getUsername());


            RefreshTokenResponse refreshTokenResponse = refreshTokenService.createRefreshToken(user);
            RefreshToken refreshToken=refreshTokenResponse.getRefreshToken();
            String rawToken=refreshTokenResponse.getRawToken();
            refreshToken.setDeviceInfo(request.getHeader("User-Agent"));
            refreshToken.setIpAddress(request.getRemoteAddr());

            // Set refresh token in HttpOnly Secure cookie
            ResponseCookie cookie = ResponseCookie.from("refreshToken", rawToken)
                    .httpOnly(true)
                    .secure(cookieSecure)
                    .path("/api/auth")
                    .sameSite("Strict")
                    .maxAge(Duration.ofDays(7))
                    .build();
            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

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
            User user = customUserDetailsService.getUserByEmail(req.getEmail());
            if (user != null) {
                int newAttempts = user.getFailedAttempts() + 1;
                user.setFailedAttempts(newAttempts);

                if (newAttempts >= loginSecurityProperties.getMaxFailedAttempts()) {
                    user.setAccountLocked(true);
                    user.setLockTime(new Date().toInstant());
                    log.warn("Account locked for user: {}", user.getEmail());
                }
                customUserDetailsService.save(user);
            }
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

    /*
    curl --location --request POST 'http://localhost:8080/api/auth/refresh' \
    --header 'Content-Type: application/json' \
    --header 'Cookie: refreshToken=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ5b3VuZXNzZWdhbWVzQGdtYWlsLmNvbSIsImlhdCI6MTc2MDQ1NjQ4MiwiZXhwIjoxNzYxMDYxMjgyfQ.QBwM3TGyFzg66DI6qzW3gRoSSDDRFiisvVdmKrbAcSWIEVp60rgHk_2hbvSQbuNCp8RWkRZZrSBWgYi-NGyw7Q'
    Response
    {
    "token": "XXXX"
    }

     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@CookieValue(name = "refreshToken", required = false) String refreshTokenStr,
                                          HttpServletRequest request,
                                          HttpServletResponse response) {
        String clientIP = getClientIP(request);

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
            String jti = UUID.randomUUID().toString();
            // Generate new access token
            String newAccessToken = jwtUtil.generateToken(user.getEmail(), roles,jti);

            // Rotate refresh token for better security
            RefreshTokenResponse refreshTokenResponse = refreshTokenService.rotateRefreshToken(refreshToken);
            String rawToken=refreshTokenResponse.getRawToken();
            RefreshToken newRefreshToken =refreshTokenResponse.getRefreshToken();
            // Update cookie with new refresh token
            ResponseCookie cookie = ResponseCookie.from("refreshToken", rawToken)
                    .httpOnly(true)
                    .secure(cookieSecure)
                    .path("/api/auth")
                    .sameSite("Strict")
                    .maxAge(Duration.ofDays(7))
                    .build();
            response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

            log.info("Token refreshed successfully from IP: {}", clientIP);
            return ResponseEntity.ok(Map.of("token", newAccessToken));

        } catch (Exception e) {
            log.error("Token refresh failed from IP: {} - {}", clientIP, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid or expired refresh token"));
        }
    }


    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name = "refreshToken", required = false) String refreshTokenStr,
                                    @RequestHeader(value = "Authorization", required = false) String authHeader,
                                    HttpServletRequest request,
                                    HttpServletResponse response) {
        String clientIP = getClientIP(request);

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
        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/api/auth")
                .maxAge(0)
                .build();
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        log.info("User logged out from IP: {}", clientIP);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}