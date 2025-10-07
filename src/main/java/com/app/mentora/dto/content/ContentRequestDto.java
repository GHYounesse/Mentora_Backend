package com.app.mentora.dto.content;

import com.app.mentora.enums.Category;
import com.app.mentora.model.auth.User;
import com.app.mentora.model.content.Content;
import jakarta.validation.constraints.NotBlank;

public class ContentRequestDto {
    @NotBlank
    private String title;
    private String body;
    private String category;
    private boolean premium;
    private String videoUrl;
    private String thumbnailUrl;

    public ContentRequestDto() {
    }

    public Content toEntity(User user) {
        Content c = new Content();
        c.setTitle(title);
        c.setBody(body);
        c.setAuthor(user);
        c.setCategory(Category.valueOf(category.toUpperCase()));
        c.setPremium(premium);
        c.setVideoUrl(videoUrl);
        c.setThumbnailUrl(thumbnailUrl);
        return c;
    }

    public @NotBlank String getTitle() {
        return this.title;
    }

    public String getBody() {
        return this.body;
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

    public void setTitle(@NotBlank String title) {
        this.title = title;
    }

    public void setBody(String body) {
        this.body = body;
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

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof ContentRequestDto)) return false;
        final ContentRequestDto other = (ContentRequestDto) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$title = this.getTitle();
        final Object other$title = other.getTitle();
        if (this$title == null ? other$title != null : !this$title.equals(other$title)) return false;
        final Object this$body = this.getBody();
        final Object other$body = other.getBody();
        if (this$body == null ? other$body != null : !this$body.equals(other$body)) return false;
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
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof ContentRequestDto;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $title = this.getTitle();
        result = result * PRIME + ($title == null ? 43 : $title.hashCode());
        final Object $body = this.getBody();
        result = result * PRIME + ($body == null ? 43 : $body.hashCode());
        final Object $category = this.getCategory();
        result = result * PRIME + ($category == null ? 43 : $category.hashCode());
        result = result * PRIME + (this.isPremium() ? 79 : 97);
        final Object $videoUrl = this.getVideoUrl();
        result = result * PRIME + ($videoUrl == null ? 43 : $videoUrl.hashCode());
        final Object $thumbnailUrl = this.getThumbnailUrl();
        result = result * PRIME + ($thumbnailUrl == null ? 43 : $thumbnailUrl.hashCode());
        return result;
    }

    public String toString() {
        return "ContentRequestDto(title=" + this.getTitle() + ", body=" + this.getBody() + ", category=" + this.getCategory() + ", premium=" + this.isPremium() + ", videoUrl=" + this.getVideoUrl() + ", thumbnailUrl=" + this.getThumbnailUrl() + ")";
    }
}
