package com.app.mentora.service.subscription;

import com.app.mentora.model.auth.User;

public interface PaymentService {
    /**
     * Charges a user's payment method for a subscription plan.
     *
     * @param user          The user to be charged
     * @param plan          The subscription plan (e.g., "monthly", "yearly")
     * @param paymentToken  The token or ID provided by the frontend (Stripe/PayPal)
     * @return The payment ID or transaction reference from the provider
     */
    String charge(User user, String plan, String paymentToken);

    /** @return The payment provider name ("Stripe", "PayPal", etc.) */
    String getProviderName();
}

