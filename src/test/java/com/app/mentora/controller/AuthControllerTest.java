package com.app.mentora.controller;


import com.app.mentora.dto.LoginSecurityProperties;
import com.app.mentora.dto.RefreshTokenResponse;
import com.app.mentora.dto.auth.LoginUserDto;
import com.app.mentora.dto.auth.SignupUserDto;
import com.app.mentora.model.auth.User;
import com.app.mentora.model.token.RefreshToken;
import com.app.mentora.repository.auth.UserRepository;
import com.app.mentora.security.JwtAuthentificationFilter;
import com.app.mentora.security.JwtUtil;
import com.app.mentora.service.auth.CustomUserDetailsService;
import com.app.mentora.service.limit_rate.RateLimitService;
import com.app.mentora.service.token.RefreshTokenService;
import com.app.mentora.service.token.TokenBlacklistService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthenticationManager authManager;

    @MockitoBean
    private UserRepository userRepo;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private JwtUtil jwtUtil;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private RefreshTokenService refreshTokenService;

    @MockitoBean
    private RateLimitService rateLimitService;

    @MockitoBean
    private TokenBlacklistService blacklistService;

    @MockitoBean
    private LoginSecurityProperties loginSecurityProperties;
    @MockitoBean
    private JwtAuthentificationFilter jwtFilter;

    private SignupUserDto signupDto;
    private LoginUserDto loginDto;
    private User testUser;
    private RefreshToken refreshToken;

    @BeforeEach
    void setupMocks() throws Exception {
        doAnswer(invocation -> {
            FilterChain chain = invocation.getArgument(2);
            HttpServletRequest req = invocation.getArgument(0);
            HttpServletResponse res = invocation.getArgument(1);
            // Simply continue the filter chain without checking JWT
            chain.doFilter(req, res);
            return null;
        }).when(jwtFilter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
    }
    @BeforeEach
    void setUp() {
        // Setup test DTOs
        signupDto = new SignupUserDto();
        signupDto.setEmail("test@example.com");
        signupDto.setPassword("SecurePass123!");

        loginDto = new LoginUserDto();
        loginDto.setEmail("test@example.com");
        loginDto.setPassword("SecurePass123!");

        // Setup test user
        testUser = new User();
        testUser.setId(1L);
        testUser.setEmail("test@example.com");
        testUser.setPassword("encodedPassword");
        testUser.setRoles(Set.of("ROLE_USER"));
        testUser.setAccountLocked(false);
        testUser.setFailedAttempts(0);

        // Setup refresh token
        refreshToken = new RefreshToken();
        refreshToken.setId(1L);
        refreshToken.setToken("hashedRefreshToken");
        refreshToken.setUser(testUser);
        refreshToken.setExpiryDate(Instant.now().plus(Duration.ofDays(7)));
        refreshToken.setIpAddress("127.0.0.1");
        refreshToken.setDeviceInfo("Test Device");

        // Default mock behaviors
        when(rateLimitService.tryConsume(anyString())).thenReturn(true);
        when(loginSecurityProperties.getMaxFailedAttempts()).thenReturn(5);
        when(loginSecurityProperties.getLockTimeDuration()).thenReturn(900000L); // 15 minutes
    }

    @Nested
    @DisplayName("Signup Tests")
    class SignupTests {

        @Test
        @DisplayName("Should register new user successfully")
        void shouldRegisterNewUserSuccessfully() throws Exception {
            when(userRepo.existsByEmail(signupDto.getEmail())).thenReturn(false);
            when(passwordEncoder.encode(signupDto.getPassword())).thenReturn("encodedPassword");

            mockMvc.perform(post("/api/v1/auth/signup")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signupDto)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.message").value("User registered successfully"));

            verify(userRepo).save(any(User.class));
        }

        @Test
        @DisplayName("Should return success even when email exists (prevent enumeration)")
        void shouldReturnSuccessWhenEmailExists() throws Exception {
            when(userRepo.existsByEmail(signupDto.getEmail())).thenReturn(true);

            mockMvc.perform(post("/api/v1/auth/signup")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signupDto)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.message").value("User registered successfully"));

            verify(userRepo, never()).save(any(User.class));
        }

        @Test
        @DisplayName("Should reject signup when rate limit exceeded")
        void shouldRejectSignupWhenRateLimitExceeded() throws Exception {
            when(rateLimitService.tryConsume(anyString())).thenReturn(false);

            mockMvc.perform(post("/api/v1/auth/signup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signupDto)))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(jsonPath("$.error").value("Too many requests. Please try again later."));
        }

        @Test
        @DisplayName("Should reject invalid email format")
        void shouldRejectInvalidEmail() throws Exception {
            signupDto.setEmail("invalid-email");

            mockMvc.perform(post("/api/v1/auth/signup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signupDto)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Login Tests")
    class LoginTests {

        @Test
        @DisplayName("Should login successfully with valid credentials")
        void shouldLoginSuccessfully() throws Exception {
            // Mock authentication
            Authentication auth = mock(Authentication.class);
            org.springframework.security.core.userdetails.User userDetails =
                    new org.springframework.security.core.userdetails.User(
                            testUser.getEmail(),
                            testUser.getPassword(),
                            List.of(new SimpleGrantedAuthority("ROLE_USER"))
                    );

            when(customUserDetailsService.getUserByEmail(loginDto.getEmail())).thenReturn(testUser);
            when(authManager.authenticate(any())).thenReturn(auth);
            when(auth.getPrincipal()).thenReturn(userDetails);
            when(jwtUtil.generateToken(anyString(), anyList(), anyString())).thenReturn("jwt-token");

            RefreshTokenResponse refreshTokenResponse = new RefreshTokenResponse();
            refreshTokenResponse.setRefreshToken(refreshToken);
            refreshTokenResponse.setRawToken("raw-refresh-token");
            when(refreshTokenService.createRefreshToken(any(User.class))).thenReturn(refreshTokenResponse);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.token").value("jwt-token"))
                    .andExpect(jsonPath("$.email").value(loginDto.getEmail()))
                    .andExpect(cookie().exists("refreshToken"))
                    .andExpect(cookie().httpOnly("refreshToken", true))
                    .andExpect(cookie().path("refreshToken", "/api/auth"));

            verify(rateLimitService).clearBucket(anyString());
        }

        @Test
        @DisplayName("Should reject login with invalid credentials")
        void shouldRejectInvalidCredentials() throws Exception {
            when(customUserDetailsService.getUserByEmail(loginDto.getEmail())).thenReturn(testUser);
            when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("Invalid credentials"));

            verify(customUserDetailsService).save(argThat(user ->
                    user.getFailedAttempts() == 1
            ));
        }

        @Test
        @DisplayName("Should lock account after max failed attempts")
        void shouldLockAccountAfterMaxFailedAttempts() throws Exception {
            testUser.setFailedAttempts(4); // One more attempt will lock
            when(customUserDetailsService.getUserByEmail(loginDto.getEmail())).thenReturn(testUser);
            when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isUnauthorized());

            verify(customUserDetailsService).save(argThat(user ->
                    user.getFailedAttempts() == 5 &&
                            user.isAccountLocked() &&
                            user.getLockTime() != null
            ));
        }

        @Test
        @DisplayName("Should reject login for locked account")
        void shouldRejectLoginForLockedAccount() throws Exception {
            testUser.setAccountLocked(true);
            testUser.setLockTime(Instant.now());
            when(customUserDetailsService.getUserByEmail(loginDto.getEmail())).thenReturn(testUser);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").exists());
        }

        @Test
        @DisplayName("Should auto-unlock account after lock duration")
        void shouldAutoUnlockAccountAfterLockDuration() throws Exception {
            testUser.setAccountLocked(true);
            testUser.setLockTime(Instant.now().minus(Duration.ofMinutes(20)));
            testUser.setFailedAttempts(5);

            Authentication auth = mock(Authentication.class);
            org.springframework.security.core.userdetails.User userDetails =
                    new org.springframework.security.core.userdetails.User(
                            testUser.getEmail(),
                            testUser.getPassword(),
                            List.of(new SimpleGrantedAuthority("ROLE_USER"))
                    );

            when(customUserDetailsService.getUserByEmail(loginDto.getEmail())).thenReturn(testUser);
            when(authManager.authenticate(any())).thenReturn(auth);
            when(auth.getPrincipal()).thenReturn(userDetails);
            when(jwtUtil.generateToken(anyString(), anyList(), anyString())).thenReturn("jwt-token");

            RefreshTokenResponse refreshTokenResponse = new RefreshTokenResponse();
            refreshTokenResponse.setRefreshToken(refreshToken);
            refreshTokenResponse.setRawToken("raw-refresh-token");
            when(refreshTokenService.createRefreshToken(any(User.class))).thenReturn(refreshTokenResponse);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isOk());

            verify(customUserDetailsService).save(argThat(user ->
                    !user.isAccountLocked() &&
                            user.getFailedAttempts() == 0 &&
                            user.getLockTime() == null
            ));
        }

        @Test
        @DisplayName("Should reject login when rate limit exceeded")
        void shouldRejectLoginWhenRateLimitExceeded() throws Exception {
            when(rateLimitService.tryConsume(anyString())).thenReturn(false);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isTooManyRequests())
                    .andExpect(jsonPath("$.error").value("Too many login attempts. Please try again later."));
        }

        @Test
        @DisplayName("Should handle disabled account")
        void shouldHandleDisabledAccount() throws Exception {
            when(customUserDetailsService.getUserByEmail(loginDto.getEmail())).thenReturn(testUser);
            when(authManager.authenticate(any())).thenThrow(new DisabledException("Account disabled"));

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("Account is disabled"));
        }

        @Test
        @DisplayName("Should return unauthorized for non-existent user")
        void shouldReturnUnauthorizedForNonExistentUser() throws Exception {
            when(customUserDetailsService.getUserByEmail(loginDto.getEmail())).thenReturn(null);

            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(loginDto)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("Invalid credentials"));
        }
    }

    @Nested
    @DisplayName("Refresh Token Tests")
    class RefreshTokenTests {

        @Test
        @DisplayName("Should refresh token successfully")
        void shouldRefreshTokenSuccessfully() throws Exception {
            String hashedToken = RefreshToken.hashToken("raw-refresh-token");
            when(refreshTokenService.findByToken(hashedToken)).thenReturn(Optional.of(refreshToken));
            when(refreshTokenService.verifyExpiration(refreshToken)).thenReturn(refreshToken);
            when(blacklistService.areAllUserTokensBlacklisted(testUser.getId())).thenReturn(false);
            when(jwtUtil.generateToken(anyString(), anyList(), anyString())).thenReturn("new-jwt-token");

            RefreshTokenResponse newRefreshTokenResponse = new RefreshTokenResponse();
            RefreshToken newRefreshToken = new RefreshToken();
            newRefreshToken.setToken("new-hashed-token");
            newRefreshTokenResponse.setRefreshToken(newRefreshToken);
            newRefreshTokenResponse.setRawToken("new-raw-token");
            when(refreshTokenService.rotateRefreshToken(refreshToken)).thenReturn(newRefreshTokenResponse);

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie("refreshToken", "raw-refresh-token"))
                            .header("User-Agent", "Test Agent")
                            .with(request -> {
                                request.setRemoteAddr("127.0.0.1");
                                return request;
                            }))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.token").value("new-jwt-token"))
                    .andExpect(cookie().exists("refreshToken"));

            verify(refreshTokenService).LimitRefreshTokenPerUserActive(testUser.getId());
        }

        @Test
        @DisplayName("Should reject refresh with missing token")
        void shouldRejectRefreshWithMissingToken() throws Exception {
            mockMvc.perform(post("/api/v1/auth/refresh"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("Refresh token is missing"));
        }

        @Test
        @DisplayName("Should reject refresh with invalid token")
        void shouldRejectRefreshWithInvalidToken() throws Exception {
            String hashedToken = RefreshToken.hashToken("invalid-token");
            when(refreshTokenService.findByToken(hashedToken)).thenReturn(Optional.empty());

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie("refreshToken", "invalid-token")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("Invalid or expired refresh token"));
        }

        @Test
        @DisplayName("Should reject refresh when all tokens are blacklisted")
        void shouldRejectRefreshWhenAllTokensBlacklisted() throws Exception {
            String hashedToken = RefreshToken.hashToken("raw-refresh-token");
            when(refreshTokenService.findByToken(hashedToken)).thenReturn(Optional.of(refreshToken));
            when(refreshTokenService.verifyExpiration(refreshToken)).thenReturn(refreshToken);
            when(blacklistService.areAllUserTokensBlacklisted(testUser.getId())).thenReturn(true);

            mockMvc.perform(post("/api/v1/auth/refresh")
                            .cookie(new Cookie("refreshToken", "raw-refresh-token"))
                            .with(request -> {
                                request.setRemoteAddr("127.0.0.1");
                                return request;
                            }))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("All tokens revoked. Please login again."));
        }
    }

    @Nested
    @DisplayName("Logout Tests")
    class LogoutTests {

        @Test
        @DisplayName("Should logout successfully with access and refresh tokens")
        void shouldLogoutSuccessfully() throws Exception {
            String accessToken = "Bearer jwt-token";
            when(jwtUtil.getJtiFromToken("jwt-token")).thenReturn("jti-123");
            when(jwtUtil.getExpirationDateFromToken("jwt-token")).thenReturn(new Date());

            mockMvc.perform(post("/api/v1/auth/logout")
                            .header("Authorization", accessToken)
                            .cookie(new Cookie("refreshToken", "refresh-token")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Logged out successfully"))
                    .andExpect(cookie().maxAge("refreshToken", 0));

            verify(blacklistService).blacklistToken(eq("jti-123"), any(Date.class));
            verify(refreshTokenService).revokeToken("refresh-token");
        }

        @Test
        @DisplayName("Should logout with only refresh token")
        void shouldLogoutWithOnlyRefreshToken() throws Exception {
            mockMvc.perform(post("/api/v1/auth/logout")
                            .cookie(new Cookie("refreshToken", "refresh-token")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Logged out successfully"));

            verify(refreshTokenService).revokeToken("refresh-token");
            verify(blacklistService, never()).blacklistToken(anyString(), any(Date.class));
        }

        @Test
        @DisplayName("Should logout with only access token")
        void shouldLogoutWithOnlyAccessToken() throws Exception {
            String accessToken = "Bearer jwt-token";
            when(jwtUtil.getJtiFromToken("jwt-token")).thenReturn("jti-123");
            when(jwtUtil.getExpirationDateFromToken("jwt-token")).thenReturn(new Date());

            mockMvc.perform(post("/api/v1/auth/logout")
                            .header("Authorization", accessToken))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Logged out successfully"));

            verify(blacklistService).blacklistToken(eq("jti-123"), any(Date.class));
            verify(refreshTokenService, never()).revokeToken(anyString());
        }

        @Test
        @DisplayName("Should logout without any tokens")
        void shouldLogoutWithoutAnyTokens() throws Exception {
            mockMvc.perform(post("/api/v1/auth/logout"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").value("Logged out successfully"));

            verify(blacklistService, never()).blacklistToken(anyString(), any(Date.class));
            verify(refreshTokenService, never()).revokeToken(anyString());
        }
    }
}
