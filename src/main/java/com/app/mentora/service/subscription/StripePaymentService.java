package com.app.mentora.service.subscription;

import com.app.mentora.exception.PaymentFailedException;
import com.app.mentora.model.auth.User;
import com.stripe.model.Charge;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service("stripePaymentService")
public class StripePaymentService implements PaymentService {

    @Value("${stripe.secret.key}")
    private String stripeSecretKey;

    @PostConstruct
    public void init() {
        com.stripe.Stripe.apiKey = stripeSecretKey;
    }

    @Override
    public String charge(User user, String plan, String paymentToken) {
        try {
            long amount = plan.equalsIgnoreCase("monthly") ? 1000L : 10000L;

            Map<String, Object> chargeParams = new HashMap<>();
            chargeParams.put("amount", amount);
            chargeParams.put("currency", "usd");
            chargeParams.put("source", paymentToken);
            chargeParams.put("description", "Mentora " + plan + " subscription for " + user.getEmail());

            Charge charge = Charge.create(chargeParams);
            return charge.getId();
        } catch (Exception e) {
            throw new PaymentFailedException("Stripe payment failed: " + e.getMessage());
        }
    }

    @Override
    public String getProviderName() {
        return "stripe";
    }
}

