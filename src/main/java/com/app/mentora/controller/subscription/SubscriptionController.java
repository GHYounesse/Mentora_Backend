package com.app.mentora.controller.subscription;

import com.app.mentora.dto.subscription.SubscriptionRequestDto;
import com.app.mentora.dto.subscription.SubscriptionResponseDto;
import com.app.mentora.service.auth.CustomUserDetailsService;
import com.app.mentora.service.subscription.SubscriptionService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/subscription")
public class SubscriptionController {
    private final SubscriptionService subscriptionService;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    public SubscriptionController(SubscriptionService subscriptionService) {
        this.subscriptionService = subscriptionService;
    }

    @PostMapping("/subscribe")
    public ResponseEntity<SubscriptionResponseDto> subscribe(@RequestBody @Valid SubscriptionRequestDto dto,
                                                             Authentication authentication) {
        String email = authentication.getName();
        Long userId = customUserDetailsService.getUserIdFromToken(email);
        SubscriptionResponseDto response = subscriptionService.subscribe(userId, dto);
        return ResponseEntity.ok(response);
    }
}
