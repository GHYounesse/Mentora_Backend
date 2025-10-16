package com.app.mentora.controller;

import com.app.mentora.dto.profile.ChangePasswordRequest;
import com.app.mentora.dto.profile.UpdateProfileDto;
import com.app.mentora.dto.profile.UpdateProfileRequest;
import com.app.mentora.model.auth.User;
import com.app.mentora.service.profile.ProfileService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class ProfileController {
    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @PutMapping("/update")
    public ResponseEntity<String> updateProfile(@Valid @RequestBody UpdateProfileDto request,
                                              Authentication authentication) {
        String email = authentication.getName(); // from JWT
        User updated = profileService.updateProfile(email, request);
        return ResponseEntity.ok("Profile updated successfully");
    }

    @PutMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest request,
                                                 Authentication authentication) {
        String email = authentication.getName();
        profileService.changePassword(email, request);
        return ResponseEntity.ok("Password updated successfully");
    }
}

