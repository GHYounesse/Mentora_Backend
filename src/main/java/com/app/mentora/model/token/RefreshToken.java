package com.app.mentora.model.token;


import com.app.mentora.model.auth.User;
import jakarta.persistence.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private String deviceInfo;
    @Column(nullable = false)
    private String ipAddress;

    // Constructors
    public RefreshToken() {
        this.createdAt = Instant.now();
    }

    public RefreshToken(String token, User user, Instant expiryDate) {
        this.token = token;
        this.user = user;
        this.expiryDate = expiryDate;
        this.createdAt = Instant.now();
    }

    public static String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // Should never happen for "SHA-256", but just in case:
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    // Getters and Setters


    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }

    public Long getId() {
        return this.id;
    }

    public String getToken() {
        return this.token;
    }

    public User getUser() {
        return this.user;
    }

    public Instant getExpiryDate() {
        return this.expiryDate;
    }

    public boolean isRevoked() {
        return this.revoked;
    }

    public Instant getCreatedAt() {
        return this.createdAt;
    }

    public String getDeviceInfo() {
        return this.deviceInfo;
    }

    public String getIpAddress() {
        return this.ipAddress;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setToken(String token) {
        this.token =token;

    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setExpiryDate(Instant expiryDate) {
        this.expiryDate = expiryDate;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof RefreshToken)) return false;
        final RefreshToken other = (RefreshToken) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$id = this.getId();
        final Object other$id = other.getId();
        if (this$id == null ? other$id != null : !this$id.equals(other$id)) return false;
        final Object this$token = this.getToken();
        final Object other$token = other.getToken();
        if (this$token == null ? other$token != null : !this$token.equals(other$token)) return false;
        final Object this$user = this.getUser();
        final Object other$user = other.getUser();
        if (this$user == null ? other$user != null : !this$user.equals(other$user)) return false;
        final Object this$expiryDate = this.getExpiryDate();
        final Object other$expiryDate = other.getExpiryDate();
        if (this$expiryDate == null ? other$expiryDate != null : !this$expiryDate.equals(other$expiryDate))
            return false;
        if (this.isRevoked() != other.isRevoked()) return false;
        final Object this$createdAt = this.getCreatedAt();
        final Object other$createdAt = other.getCreatedAt();
        if (this$createdAt == null ? other$createdAt != null : !this$createdAt.equals(other$createdAt)) return false;
        final Object this$deviceInfo = this.getDeviceInfo();
        final Object other$deviceInfo = other.getDeviceInfo();
        if (this$deviceInfo == null ? other$deviceInfo != null : !this$deviceInfo.equals(other$deviceInfo))
            return false;
        final Object this$ipAddress = this.getIpAddress();
        final Object other$ipAddress = other.getIpAddress();
        if (this$ipAddress == null ? other$ipAddress != null : !this$ipAddress.equals(other$ipAddress)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof RefreshToken;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $id = this.getId();
        result = result * PRIME + ($id == null ? 43 : $id.hashCode());
        final Object $token = this.getToken();
        result = result * PRIME + ($token == null ? 43 : $token.hashCode());
        final Object $user = this.getUser();
        result = result * PRIME + ($user == null ? 43 : $user.hashCode());
        final Object $expiryDate = this.getExpiryDate();
        result = result * PRIME + ($expiryDate == null ? 43 : $expiryDate.hashCode());
        result = result * PRIME + (this.isRevoked() ? 79 : 97);
        final Object $createdAt = this.getCreatedAt();
        result = result * PRIME + ($createdAt == null ? 43 : $createdAt.hashCode());
        final Object $deviceInfo = this.getDeviceInfo();
        result = result * PRIME + ($deviceInfo == null ? 43 : $deviceInfo.hashCode());
        final Object $ipAddress = this.getIpAddress();
        result = result * PRIME + ($ipAddress == null ? 43 : $ipAddress.hashCode());
        return result;
    }

    public String toString() {
        return "RefreshToken(id=" + this.getId() + ", token=" + this.getToken() + ", user=" + this.getUser() + ", expiryDate=" + this.getExpiryDate() + ", revoked=" + this.isRevoked() + ", createdAt=" + this.getCreatedAt() + ", deviceInfo=" + this.getDeviceInfo() + ", ipAddress=" + this.getIpAddress() + ")";
    }
}
