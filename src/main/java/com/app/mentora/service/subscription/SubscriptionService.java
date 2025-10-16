package com.app.mentora.service.subscription;

import com.app.mentora.dto.subscription.SubscriptionRequestDto;
import com.app.mentora.dto.subscription.SubscriptionResponseDto;
import com.app.mentora.model.auth.User;
import com.app.mentora.model.subscription.Subscription;
import com.app.mentora.repository.SubscriptionRepository;
import com.app.mentora.repository.auth.UserRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.time.LocalDate;

@Service
public class SubscriptionService {

    private final SubscriptionRepository subscriptionRepository;
    private final UserRepository userRepository;
    private final @Qualifier("mockPaymentService") PaymentService paymentService;

    public SubscriptionService(SubscriptionRepository subscriptionRepository, UserRepository userRepository, @Qualifier("mockPaymentService") PaymentService paymentService) {
        this.subscriptionRepository = subscriptionRepository;
        this.userRepository = userRepository;
        this.paymentService = paymentService;
    }

    public SubscriptionResponseDto subscribe(Long userId, SubscriptionRequestDto dto) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Call payment provider
        String paymentId = paymentService.charge(user, dto.getPlan(), dto.getPaymentToken());

        Subscription subscription = new Subscription();
        subscription.setUser(user);
        subscription.setPlan(dto.getPlan());
        subscription.setPaymentProvider(paymentService.getProviderName());
        subscription.setPaymentId(paymentId);
        subscription.setStartDate(LocalDate.now());
        subscription.setEndDate(LocalDate.now().plusMonths(dto.getPlan().equals("monthly") ? 1 : 12));
        subscription.setActive(true);

        subscriptionRepository.save(subscription);

        // Update user role
        user.addRole("ROLE_PREMIUM");
        userRepository.save(user);

        return SubscriptionResponseDto.from(subscription);
    }

}
