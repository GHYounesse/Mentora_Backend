package com.app.mentora.dto.subscription;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class SubscriptionRequestDto {
    private String plan;
    private String paymentToken;

    public String getPlan() {
        return this.plan;
    }

    public String getPaymentToken() {
        return this.paymentToken;
    }

    public void setPlan(String plan) {
        this.plan = plan;
    }

    public void setPaymentToken(String paymentToken) {
        this.paymentToken = paymentToken;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof SubscriptionRequestDto)) return false;
        final SubscriptionRequestDto other = (SubscriptionRequestDto) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$plan = this.getPlan();
        final Object other$plan = other.getPlan();
        if (this$plan == null ? other$plan != null : !this$plan.equals(other$plan)) return false;
        final Object this$paymentToken = this.getPaymentToken();
        final Object other$paymentToken = other.getPaymentToken();
        if (this$paymentToken == null ? other$paymentToken != null : !this$paymentToken.equals(other$paymentToken))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof SubscriptionRequestDto;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $plan = this.getPlan();
        result = result * PRIME + ($plan == null ? 43 : $plan.hashCode());
        final Object $paymentToken = this.getPaymentToken();
        result = result * PRIME + ($paymentToken == null ? 43 : $paymentToken.hashCode());
        return result;
    }

    public String toString() {
        return "SubscriptionRequestDto(plan=" + this.getPlan() + ", paymentToken=" + this.getPaymentToken() + ")";
    }
}
