package com.app.mentora.dto.subscription;

import com.app.mentora.model.subscription.Subscription;

import java.time.LocalDate;

public class SubscriptionResponseDto {
    private Long id;
    private String plan;
    private LocalDate startDate;
    private LocalDate endDate;
    private boolean active;

    public SubscriptionResponseDto() {
    }

    public SubscriptionResponseDto(Long id, String plan, LocalDate startDate, LocalDate endDate, boolean active) {
        this.id = id;
        this.plan = plan;
        this.startDate = startDate;
        this.endDate = endDate;
        this.active = active;
    }

    public Long getId() {
        return this.id;
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

    public void setId(Long id) {
        this.id = id;
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

    public static SubscriptionResponseDto from(Subscription subscription) {

        return new SubscriptionResponseDto(subscription.getId(), subscription.getPlan(), subscription.getStartDate(), subscription.getEndDate(), subscription.isActive());
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof SubscriptionResponseDto)) return false;
        final SubscriptionResponseDto other = (SubscriptionResponseDto) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$id = this.getId();
        final Object other$id = other.getId();
        if (this$id == null ? other$id != null : !this$id.equals(other$id)) return false;
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
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof SubscriptionResponseDto;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $id = this.getId();
        result = result * PRIME + ($id == null ? 43 : $id.hashCode());
        final Object $plan = this.getPlan();
        result = result * PRIME + ($plan == null ? 43 : $plan.hashCode());
        final Object $startDate = this.getStartDate();
        result = result * PRIME + ($startDate == null ? 43 : $startDate.hashCode());
        final Object $endDate = this.getEndDate();
        result = result * PRIME + ($endDate == null ? 43 : $endDate.hashCode());
        result = result * PRIME + (this.isActive() ? 79 : 97);
        return result;
    }

    public String toString() {
        return "SubscriptionResponseDto(id=" + this.getId() + ", plan=" + this.getPlan() + ", startDate=" + this.getStartDate() + ", endDate=" + this.getEndDate() + ", active=" + this.isActive() + ")";
    }
}
