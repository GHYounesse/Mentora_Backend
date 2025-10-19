package com.app.mentora.service.auth;

import com.app.mentora.dto.LoginSecurityProperties;
import com.app.mentora.model.auth.User;
import com.app.mentora.repository.auth.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.stream.Collectors;
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    private final LoginSecurityProperties loginSecurityProperties;
    public CustomUserDetailsService(UserRepository userRepository, LoginSecurityProperties loginSecurityProperties) {
        this.userRepository = userRepository;
        this.loginSecurityProperties=loginSecurityProperties;
    }
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found: "+email));
        var authorities = user.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), authorities);
    }

    public Long getUserIdFromToken(String email) {

        return userRepository.findByEmail(email)  // or findByUsername
                .orElseThrow(() -> new RuntimeException("User not found"))
                .getId();
    }
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

    }
    public void save(User user) {
        userRepository.save(user);
    }
    // Reset lock state if needed
    public long handleLock(User u) {
        long lockDuration = loginSecurityProperties.getLockTimeDuration();
        long lockTimeElapsed = Duration.between(u.getLockTime(), Instant.now()).toMillis();

        if (lockTimeElapsed >= lockDuration) {
            // Unlock account after lock duration expires
            u.setAccountLocked(false);
            u.setFailedAttempts(0);
            u.setLockTime(null);
            save(u);
            //log.info("Account unlocked automatically for user: {}", u.getEmail());
            return 0;

        } else {
            return (lockDuration - lockTimeElapsed) / 60000;

        }
    }
}
