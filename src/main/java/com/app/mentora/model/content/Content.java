package com.app.mentora.model.content;

import com.app.mentora.enums.Category;
import com.app.mentora.enums.ContentStatus;
import com.app.mentora.model.auth.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@EntityListeners(AuditingEntityListener.class)
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "content", indexes = {
        @Index(name = "idx_content_category", columnList = "category"),
        @Index(name = "idx_content_premium", columnList = "isPremium"),
        @Index(name = "idx_content_user", columnList = "user_id")
})
public class Content {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String title;
    private String body;
    @Enumerated(EnumType.STRING)
    private Category category;

    @Enumerated(EnumType.STRING)
    private ContentStatus status = ContentStatus.DRAFT;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User author;

    private boolean isPremium;

    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;
    @LastModifiedDate
    private LocalDateTime updatedAt;

    private String videoUrl;
    private String thumbnailUrl;


    public Long getId() {
        return this.id;
    }

    public String getTitle() {
        return this.title;
    }

    public String getBody() {
        return this.body;
    }

    public Category getCategory() {
        return this.category;
    }

    public ContentStatus getStatus() {
        return this.status;
    }

    public User getAuthor() {
        return this.author;
    }

    public boolean isPremium() {
        return this.isPremium;
    }

    public LocalDateTime getCreatedAt() {
        return this.createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return this.updatedAt;
    }

    public String getVideoUrl() {
        return this.videoUrl;
    }

    public String getThumbnailUrl() {
        return this.thumbnailUrl;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public void setCategory(Category category) {
        this.category = category;
    }

    public void setStatus(ContentStatus status) {
        this.status = status;
    }

    public void setAuthor(User author) {
        this.author = author;
    }

    public void setPremium(boolean isPremium) {
        this.isPremium = isPremium;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public void setVideoUrl(String videoUrl) {
        this.videoUrl = videoUrl;
    }

    public void setThumbnailUrl(String thumbnailUrl) {
        this.thumbnailUrl = thumbnailUrl;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof Content)) return false;
        final Content other = (Content) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$id = this.getId();
        final Object other$id = other.getId();
        if (this$id == null ? other$id != null : !this$id.equals(other$id)) return false;
        final Object this$title = this.getTitle();
        final Object other$title = other.getTitle();
        if (this$title == null ? other$title != null : !this$title.equals(other$title)) return false;
        final Object this$body = this.getBody();
        final Object other$body = other.getBody();
        if (this$body == null ? other$body != null : !this$body.equals(other$body)) return false;
        final Object this$category = this.getCategory();
        final Object other$category = other.getCategory();
        if (this$category == null ? other$category != null : !this$category.equals(other$category)) return false;
        final Object this$status = this.getStatus();
        final Object other$status = other.getStatus();
        if (this$status == null ? other$status != null : !this$status.equals(other$status)) return false;
        final Object this$user = this.getAuthor();
        final Object other$user = other.getAuthor();
        if (this$user == null ? other$user != null : !this$user.equals(other$user)) return false;
        if (this.isPremium() != other.isPremium()) return false;
        final Object this$createdAt = this.getCreatedAt();
        final Object other$createdAt = other.getCreatedAt();
        if (this$createdAt == null ? other$createdAt != null : !this$createdAt.equals(other$createdAt)) return false;
        final Object this$updatedAt = this.getUpdatedAt();
        final Object other$updatedAt = other.getUpdatedAt();
        if (this$updatedAt == null ? other$updatedAt != null : !this$updatedAt.equals(other$updatedAt)) return false;
        final Object this$videoUrl = this.getVideoUrl();
        final Object other$videoUrl = other.getVideoUrl();
        if (this$videoUrl == null ? other$videoUrl != null : !this$videoUrl.equals(other$videoUrl)) return false;
        final Object this$thumbnailUrl = this.getThumbnailUrl();
        final Object other$thumbnailUrl = other.getThumbnailUrl();
        if (this$thumbnailUrl == null ? other$thumbnailUrl != null : !this$thumbnailUrl.equals(other$thumbnailUrl))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof Content;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $id = this.getId();
        result = result * PRIME + ($id == null ? 43 : $id.hashCode());
        final Object $title = this.getTitle();
        result = result * PRIME + ($title == null ? 43 : $title.hashCode());
        final Object $body = this.getBody();
        result = result * PRIME + ($body == null ? 43 : $body.hashCode());
        final Object $category = this.getCategory();
        result = result * PRIME + ($category == null ? 43 : $category.hashCode());
        final Object $status = this.getStatus();
        result = result * PRIME + ($status == null ? 43 : $status.hashCode());
        final Object $user = this.getAuthor();
        result = result * PRIME + ($user == null ? 43 : $user.hashCode());
        result = result * PRIME + (this.isPremium() ? 79 : 97);
        final Object $createdAt = this.getCreatedAt();
        result = result * PRIME + ($createdAt == null ? 43 : $createdAt.hashCode());
        final Object $updatedAt = this.getUpdatedAt();
        result = result * PRIME + ($updatedAt == null ? 43 : $updatedAt.hashCode());
        final Object $videoUrl = this.getVideoUrl();
        result = result * PRIME + ($videoUrl == null ? 43 : $videoUrl.hashCode());
        final Object $thumbnailUrl = this.getThumbnailUrl();
        result = result * PRIME + ($thumbnailUrl == null ? 43 : $thumbnailUrl.hashCode());
        return result;
    }

    public String toString() {
        return "Content(id=" + this.getId() + ", title=" + this.getTitle() + ", body=" + this.getBody() + ", category=" + this.getCategory() + ", status=" + this.getStatus() + ", user=" + this.getAuthor() + ", isPremium=" + this.isPremium() + ", createdAt=" + this.getCreatedAt() + ", updatedAt=" + this.getUpdatedAt() + ", videoUrl=" + this.getVideoUrl() + ", thumbnailUrl=" + this.getThumbnailUrl() + ")";
    }
}
