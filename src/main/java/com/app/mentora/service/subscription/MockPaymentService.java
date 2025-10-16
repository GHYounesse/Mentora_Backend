package com.app.mentora.service.subscription;

import com.app.mentora.exception.PaymentFailedException;
import com.app.mentora.model.auth.User;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service("mockPaymentService")
//@Profile("stripe")
//@Profile("mock")
//public class StripePaymentService implements PaymentService {
public class MockPaymentService implements PaymentService {
//    @Value("${stripe.secret.key}")
//    private String stripeSecretKey;
//
//    @PostConstruct
//    public void init() {
//        com.stripe.Stripe.apiKey = stripeSecretKey;
//    }
//
//    @Override
//    public String charge(User user, String plan, String paymentToken) {
//        try {
//            // Plan pricing logic
//            long amountInCents = switch (plan.toLowerCase()) {
//                case "monthly" -> 1000L; // $10.00
//                case "yearly"  -> 10000L; // $100.00
//                default -> throw new IllegalArgumentException("Invalid plan: " + plan);
//            };
//
//            // Build charge parameters
//            Map<String, Object> chargeParams = new HashMap<>();
//            chargeParams.put("amount", amountInCents);
//            chargeParams.put("currency", "usd");
//            chargeParams.put("source", paymentToken); // obtained from frontend Stripe checkout
//            chargeParams.put("description", "Mentora " + plan + " subscription for " + user.getEmail());
//
//            // Create Stripe charge
//            Charge charge = Charge.create(chargeParams);
//            return charge.getId(); // Store this in Subscription entity
//
//        } catch (Exception e) {
//            throw new PaymentFailedException("Payment failed: " + e.getMessage());
//        }
//    }
//
//    @Override
//    public String getProviderName() {
//        return "Stripe";
//    }
    @Override
    public String charge(User user, String plan, String paymentToken) {
        // Just simulate a transaction
        return "mock_txn_" + UUID.randomUUID();
    }

    @Override
    public String getProviderName() {
        return "MockPay";
    }
}

