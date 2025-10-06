package com.app.mentora.controller;

import com.app.mentora.dto.auth.*;
import com.app.mentora.model.auth.User;
import com.app.mentora.repository.auth.UserRepository;
import com.app.mentora.security.JwtUtil;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authManager;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authManager, UserRepository userRepo,
                          PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.authManager = authManager; this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder; this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> register(@Valid @RequestBody SignupUserDto req) {
        log.info("Signup attempt for email: {}", req.getEmail());

        if (userRepo.existsByEmail(req.getEmail())) {
            log.warn("Signup failed: Email {} already in use", req.getEmail());
            return ResponseEntity.badRequest().body("Email already used");
        }

        User u = new User();
        u.setEmail(req.getEmail());
        u.setPassword(passwordEncoder.encode(req.getPassword()));
        u.setRoles(Set.of("ROLE_USER"));

        userRepo.save(u);

        log.info("User registered successfully: {}", req.getEmail());
        return ResponseEntity.ok("User registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginUserDto req) {
        log.info("Login attempt for email: {}", req.getEmail());

        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
            );

            var userDetails = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
            var roles = userDetails.getAuthorities().stream().map(a -> a.getAuthority()).toList();

            String token = jwtUtil.generateToken(userDetails.getUsername(), roles);

            log.info("Login successful for email: {}", req.getEmail());
            log.debug("Generated JWT token: {}", token);

            return ResponseEntity.ok(new JwtResponse(token));

        } catch (Exception e) {
            log.error("Login failed for email: {} - Reason: {}", req.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Login failed: " + e.getMessage());
        }
    }
}
