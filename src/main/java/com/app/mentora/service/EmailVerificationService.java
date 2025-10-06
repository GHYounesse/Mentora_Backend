package com.app.mentora.service;

import com.app.mentora.repository.auth.UserRepository;
import com.app.mentora.repository.auth.VerificationTokenRepository;
import com.app.mentora.service.util.EmailSenderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.app.mentora.model.auth.User;
import com.app.mentora.model.auth.VerificationToken;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
@Service
public class EmailVerificationService {
    private static final Logger log = LoggerFactory.getLogger(EmailVerificationService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private VerificationTokenRepository tokenRepository;
    @Autowired
    private EmailSenderService emailSenderService;
    /**
     * Step 1: Request email change (generate token & save pendingEmail)
     */
    public void requestEmailChange(Long userId, String newEmail) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Save pending email in user
        user.setPendingEmail(newEmail);
        userRepository.save(user);

        // Generate a verification token
        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setUserId(userId);
        verificationToken.setToken(token);
        verificationToken.setNewEmail(newEmail);
        verificationToken.setExpiresAt(LocalDateTime.now().plusHours(24));

        tokenRepository.save(verificationToken);

        // Create verification link
        String link = "http://localhost:8080/account/verify-email-change?token=" + token;

        // Send email
        emailSenderService.sendEmail(newEmail,
                "Verify your new email address",
                "Click the following link to verify your new email: " + link);
    }

    /**
     * Step 2: Verify email change
     */
    public boolean verifyEmailChange(String token) {
        log.info("Verifying email change for token: {}", token);

        Optional<VerificationToken> optToken = tokenRepository.findByToken(token);

        if (optToken.isEmpty()) {
            log.warn("Token not found: {}", token);
            return false;
        }

        VerificationToken vt = optToken.get();
        log.debug("Token found: {} for userId: {}", vt.getToken(), vt.getUserId());

        if (vt.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("Token expired for token: {}", token);
            return false;
        }

        User user = userRepository.findById(vt.getUserId())
                .orElseThrow(() -> {
                    log.error("User not found for userId: {}", vt.getUserId());
                    return new RuntimeException("User not found");
                });

        log.info("Updating email for userId: {} from {} to {}", user.getId(), user.getEmail(), vt.getNewEmail());

        // Update the email to new verified one
        user.setEmail(vt.getNewEmail());
        user.setPendingEmail(null);
        userRepository.save(user);

        log.debug("Deleting verification token: {}", vt.getToken());
        tokenRepository.delete(vt);

        log.info("Email verification successful for userId: {}", user.getId());
        return true;
    }
}
