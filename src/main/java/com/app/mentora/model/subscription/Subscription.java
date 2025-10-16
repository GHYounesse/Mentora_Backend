package com.app.mentora.model.subscription;

import com.app.mentora.model.auth.User;
import jakarta.persistence.*;

import java.time.LocalDate;

@Entity
public class Subscription {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne
    private User user;
    private String plan;
    private LocalDate startDate;
    private LocalDate endDate;
    private boolean active;

    private String paymentProvider;
    private String paymentId;

    public Subscription(Long id, User user, String plan, LocalDate startDate, LocalDate endDate, boolean active, String paymentProvider, String paymentId) {
        this.id = id;
        this.user = user;
        this.plan = plan;
        this.startDate = startDate;
        this.endDate = endDate;
        this.active = active;
        this.paymentProvider = paymentProvider;
        this.paymentId = paymentId;
    }

    public Subscription() {
    }

    public Long getId() {
        return this.id;
    }

    public User getUser() {
        return this.user;
    }

    public String getPlan() {
        return this.plan;
    }

    public LocalDate getStartDate() {
        return this.startDate;
    }

    public LocalDate getEndDate() {
        return this.endDate;
    }

    public boolean isActive() {
        return this.active;
    }

    public String getPaymentProvider() {
        return this.paymentProvider;
    }

    public String getPaymentId() {
        return this.paymentId;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setPlan(String plan) {
        this.plan = plan;
    }

    public void setStartDate(LocalDate startDate) {
        this.startDate = startDate;
    }

    public void setEndDate(LocalDate endDate) {
        this.endDate = endDate;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public void setPaymentProvider(String paymentProvider) {
        this.paymentProvider = paymentProvider;
    }

    public void setPaymentId(String paymentId) {
        this.paymentId = paymentId;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof Subscription)) return false;
        final Subscription other = (Subscription) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$id = this.getId();
        final Object other$id = other.getId();
        if (this$id == null ? other$id != null : !this$id.equals(other$id)) return false;
        final Object this$user = this.getUser();
        final Object other$user = other.getUser();
        if (this$user == null ? other$user != null : !this$user.equals(other$user)) return false;
        final Object this$plan = this.getPlan();
        final Object other$plan = other.getPlan();
        if (this$plan == null ? other$plan != null : !this$plan.equals(other$plan)) return false;
        final Object this$startDate = this.getStartDate();
        final Object other$startDate = other.getStartDate();
        if (this$startDate == null ? other$startDate != null : !this$startDate.equals(other$startDate)) return false;
        final Object this$endDate = this.getEndDate();
        final Object other$endDate = other.getEndDate();
        if (this$endDate == null ? other$endDate != null : !this$endDate.equals(other$endDate)) return false;
        if (this.isActive() != other.isActive()) return false;
        final Object this$paymentProvider = this.getPaymentProvider();
        final Object other$paymentProvider = other.getPaymentProvider();
        if (this$paymentProvider == null ? other$paymentProvider != null : !this$paymentProvider.equals(other$paymentProvider))
            return false;
        final Object this$paymentId = this.getPaymentId();
        final Object other$paymentId = other.getPaymentId();
        if (this$paymentId == null ? other$paymentId != null : !this$paymentId.equals(other$paymentId)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof Subscription;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $id = this.getId();
        result = result * PRIME + ($id == null ? 43 : $id.hashCode());
        final Object $user = this.getUser();
        result = result * PRIME + ($user == null ? 43 : $user.hashCode());
        final Object $plan = this.getPlan();
        result = result * PRIME + ($plan == null ? 43 : $plan.hashCode());
        final Object $startDate = this.getStartDate();
        result = result * PRIME + ($startDate == null ? 43 : $startDate.hashCode());
        final Object $endDate = this.getEndDate();
        result = result * PRIME + ($endDate == null ? 43 : $endDate.hashCode());
        result = result * PRIME + (this.isActive() ? 79 : 97);
        final Object $paymentProvider = this.getPaymentProvider();
        result = result * PRIME + ($paymentProvider == null ? 43 : $paymentProvider.hashCode());
        final Object $paymentId = this.getPaymentId();
        result = result * PRIME + ($paymentId == null ? 43 : $paymentId.hashCode());
        return result;
    }

    public String toString() {
        return "Subscription(id=" + this.getId() + ", user=" + this.getUser() + ", plan=" + this.getPlan() + ", startDate=" + this.getStartDate() + ", endDate=" + this.getEndDate() + ", active=" + this.isActive() + ", paymentProvider=" + this.getPaymentProvider() + ", paymentId=" + this.getPaymentId() + ")";
    }
}
