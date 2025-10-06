package com.app.mentora.service.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailSenderService {

    @Autowired
    private JavaMailSender mailSender;
    @Value("${spring.mail.username}")
    String emailFrom;
    public void sendEmail(String to, String subject, String text) {
        if (to == null || to.isBlank()) {
            throw new IllegalArgumentException("Recipient email cannot be empty");
        }

        // Trim both from and to
        String cleanFrom = emailFrom.trim();
        String cleanTo = to.trim();

        // Optional: validate email format with regex
        if (!cleanTo.matches("^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,6}$")) {
            throw new IllegalArgumentException("Invalid email format: " + cleanTo);
        }
        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom(emailFrom.trim()); // must match spring.mail.username
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }
}
