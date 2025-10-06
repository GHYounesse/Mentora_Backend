package com.app.mentora.model.auth;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "verification_tokens")
public class VerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Long userId;
    private String token;
    private String newEmail;
    private LocalDateTime expiresAt;

    public VerificationToken() {
    }

    public Long getId() {
        return this.id;
    }

    public Long getUserId() {
        return this.userId;
    }

    public String getToken() {
        return this.token;
    }

    public String getNewEmail() {
        return this.newEmail;
    }

    public LocalDateTime getExpiresAt() {
        return this.expiresAt;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setNewEmail(String newEmail) {
        this.newEmail = newEmail;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof VerificationToken)) return false;
        final VerificationToken other = (VerificationToken) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$id = this.getId();
        final Object other$id = other.getId();
        if (this$id == null ? other$id != null : !this$id.equals(other$id)) return false;
        final Object this$userId = this.getUserId();
        final Object other$userId = other.getUserId();
        if (this$userId == null ? other$userId != null : !this$userId.equals(other$userId)) return false;
        final Object this$token = this.getToken();
        final Object other$token = other.getToken();
        if (this$token == null ? other$token != null : !this$token.equals(other$token)) return false;
        final Object this$newEmail = this.getNewEmail();
        final Object other$newEmail = other.getNewEmail();
        if (this$newEmail == null ? other$newEmail != null : !this$newEmail.equals(other$newEmail)) return false;
        final Object this$expiresAt = this.getExpiresAt();
        final Object other$expiresAt = other.getExpiresAt();
        if (this$expiresAt == null ? other$expiresAt != null : !this$expiresAt.equals(other$expiresAt)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof VerificationToken;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $id = this.getId();
        result = result * PRIME + ($id == null ? 43 : $id.hashCode());
        final Object $userId = this.getUserId();
        result = result * PRIME + ($userId == null ? 43 : $userId.hashCode());
        final Object $token = this.getToken();
        result = result * PRIME + ($token == null ? 43 : $token.hashCode());
        final Object $newEmail = this.getNewEmail();
        result = result * PRIME + ($newEmail == null ? 43 : $newEmail.hashCode());
        final Object $expiresAt = this.getExpiresAt();
        result = result * PRIME + ($expiresAt == null ? 43 : $expiresAt.hashCode());
        return result;
    }

    public String toString() {
        return "VerificationToken(id=" + this.getId() + ", userId=" + this.getUserId() + ", token=" + this.getToken() + ", newEmail=" + this.getNewEmail() + ", expiresAt=" + this.getExpiresAt() + ")";
    }
}

