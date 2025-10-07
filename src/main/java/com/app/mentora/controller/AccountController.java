package com.app.mentora.controller;

import com.app.mentora.dto.auth.ChangeEmailRequest;
import com.app.mentora.service.EmailVerificationService;
import com.app.mentora.service.auth.CustomUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/account")
public class AccountController {
    private static final Logger log = LoggerFactory.getLogger(AccountController.class);
    @Autowired
    private EmailVerificationService emailVerificationService;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    /**
     * Request email change
     */
    @PostMapping("/change-email")
    public String requestEmailChange(@RequestBody ChangeEmailRequest req, Authentication authentication) {
        String email = authentication.getName();
        Long userId=customUserDetailsService.getUserIdFromToken(email);
        emailVerificationService.requestEmailChange(userId, req.getNewEmail());
        return "Verification email sent to " + req.getNewEmail();
    }
    /**
     * Verify email change
     */
    @GetMapping("/verify-email-change")
    public String verifyEmailChange(@RequestParam String token) {
        log.info("Received request to verify email change for token: {}", token);

        boolean success = emailVerificationService.verifyEmailChange(token);

        if (success) {
            log.info("Email updated successfully for token: {}", token);
            return "Email updated successfully!";
        } else {
            log.warn("Invalid or expired token: {}", token);
            return "Invalid or expired token!";
        }
    }
}
