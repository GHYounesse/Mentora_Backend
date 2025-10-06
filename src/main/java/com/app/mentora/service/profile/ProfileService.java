package com.app.mentora.service.profile;

import com.app.mentora.dto.profile.ChangePasswordRequest;
import com.app.mentora.dto.profile.UpdateProfileDto;
import com.app.mentora.dto.profile.UpdateProfileRequest;
import com.app.mentora.model.auth.User;
import com.app.mentora.repository.auth.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class ProfileService {
    final UserRepository userRepository;
    final PasswordEncoder passwordEncoder;
    public ProfileService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    public User updateProfile(String email, UpdateProfileDto updateProfileDto) {
        User user=userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        user.setEmail(email);
        user.setBio(updateProfileDto.getBio());
        user.setName(updateProfileDto.getName());
        user.setAvatarUrl(updateProfileDto.getAvatarUrl());
        return userRepository.save(user);
    }
    public void changePassword(String email, ChangePasswordRequest req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(req.oldPassword(), user.getPassword())) {
            throw new RuntimeException("Old password does not match");
        }

        user.setPassword(passwordEncoder.encode(req.newPassword()));
        userRepository.save(user);
    }
}
