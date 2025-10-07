package com.app.mentora.util;

import com.app.mentora.model.auth.User;
import com.app.mentora.repository.auth.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class AdminUserInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.password}")
    private String adminPassword;

    public AdminUserInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.findByEmail(adminEmail).isEmpty()) {
            User admin = new User();
            admin.setEmail(adminEmail);
            admin.setName("admin");
            admin.setPassword(passwordEncoder.encode(adminPassword)); // secure default password
            admin.setRoles(Set.of("ROLE_ADMIN", "ROLE_USER"));

            userRepository.save(admin);
            System.out.println("Admin user created: " + adminEmail);
        }
    }
}
