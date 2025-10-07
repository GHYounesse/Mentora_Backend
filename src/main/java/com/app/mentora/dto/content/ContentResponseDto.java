package com.app.mentora.dto.content;

import com.app.mentora.model.content.Content;

import java.time.LocalDateTime;

public class ContentResponseDto {
    private Long id;
    private String title;
    private String category;
    private boolean premium;
    private String videoUrl;
    private String thumbnailUrl;
    private LocalDateTime createdAt;

    public ContentResponseDto(Long id, String title, String category, boolean premium, String videoUrl, String thumbnailUrl, LocalDateTime createdAt) {
        this.id = id;
        this.title = title;
        this.category = category;
        this.premium = premium;
        this.videoUrl = videoUrl;
        this.thumbnailUrl = thumbnailUrl;
        this.createdAt = createdAt;
    }

    public ContentResponseDto() {
    }

    public static ContentResponseDto from(Content content) {
        return new ContentResponseDto(
                content.getId(),
                content.getTitle(),
                content.getCategory().name(),
                content.isPremium(),
                content.getVideoUrl(),
                content.getThumbnailUrl(),
                content.getCreatedAt()
        );
    }

    public Long getId() {
        return this.id;
    }

    public String getTitle() {
        return this.title;
    }

    public String getCategory() {
        return this.category;
    }

    public boolean isPremium() {
        return this.premium;
    }

    public String getVideoUrl() {
        return this.videoUrl;
    }

    public String getThumbnailUrl() {
        return this.thumbnailUrl;
    }

    public LocalDateTime getCreatedAt() {
        return this.createdAt;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public void setPremium(boolean premium) {
        this.premium = premium;
    }

    public void setVideoUrl(String videoUrl) {
        this.videoUrl = videoUrl;
    }

    public void setThumbnailUrl(String thumbnailUrl) {
        this.thumbnailUrl = thumbnailUrl;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof ContentResponseDto)) return false;
        final ContentResponseDto other = (ContentResponseDto) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$id = this.getId();
        final Object other$id = other.getId();
        if (this$id == null ? other$id != null : !this$id.equals(other$id)) return false;
        final Object this$title = this.getTitle();
        final Object other$title = other.getTitle();
        if (this$title == null ? other$title != null : !this$title.equals(other$title)) return false;
        final Object this$category = this.getCategory();
        final Object other$category = other.getCategory();
        if (this$category == null ? other$category != null : !this$category.equals(other$category)) return false;
        if (this.isPremium() != other.isPremium()) return false;
        final Object this$videoUrl = this.getVideoUrl();
        final Object other$videoUrl = other.getVideoUrl();
        if (this$videoUrl == null ? other$videoUrl != null : !this$videoUrl.equals(other$videoUrl)) return false;
        final Object this$thumbnailUrl = this.getThumbnailUrl();
        final Object other$thumbnailUrl = other.getThumbnailUrl();
        if (this$thumbnailUrl == null ? other$thumbnailUrl != null : !this$thumbnailUrl.equals(other$thumbnailUrl))
            return false;
        final Object this$createdAt = this.getCreatedAt();
        final Object other$createdAt = other.getCreatedAt();
        if (this$createdAt == null ? other$createdAt != null : !this$createdAt.equals(other$createdAt)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof ContentResponseDto;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $id = this.getId();
        result = result * PRIME + ($id == null ? 43 : $id.hashCode());
        final Object $title = this.getTitle();
        result = result * PRIME + ($title == null ? 43 : $title.hashCode());
        final Object $category = this.getCategory();
        result = result * PRIME + ($category == null ? 43 : $category.hashCode());
        result = result * PRIME + (this.isPremium() ? 79 : 97);
        final Object $videoUrl = this.getVideoUrl();
        result = result * PRIME + ($videoUrl == null ? 43 : $videoUrl.hashCode());
        final Object $thumbnailUrl = this.getThumbnailUrl();
        result = result * PRIME + ($thumbnailUrl == null ? 43 : $thumbnailUrl.hashCode());
        final Object $createdAt = this.getCreatedAt();
        result = result * PRIME + ($createdAt == null ? 43 : $createdAt.hashCode());
        return result;
    }

    public String toString() {
        return "ContentResponseDto(id=" + this.getId() + ", title=" + this.getTitle() + ", category=" + this.getCategory() + ", premium=" + this.isPremium() + ", videoUrl=" + this.getVideoUrl() + ", thumbnailUrl=" + this.getThumbnailUrl() + ", createdAt=" + this.getCreatedAt() + ")";
    }
}
