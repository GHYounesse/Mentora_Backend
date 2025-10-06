package com.app.mentora.dto.profile;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class UpdateProfileDto {


    @NotBlank(message = "Full name is required")
    @Size(max = 50, message = "Full name cannot exceed 50 characters")
    private String name;

    @NotBlank(message = "Bio is required")
    private String bio;

    @Pattern(
            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg|gif))$",
            message = "Avatar must be a valid image URL (png, jpg, jpeg, gif)"
    )
    private String avatarUrl;

    public UpdateProfileDto() {
    }


    public @NotBlank(message = "Full name is required") @Size(max = 50, message = "Full name cannot exceed 50 characters") String getName() {
        return this.name;
    }

    public @NotBlank(message = "Bio is required") String getBio() {
        return this.bio;
    }

    public @Pattern(
            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg|gif))$",
            message = "Avatar must be a valid image URL (png, jpg, jpeg, gif)"
    ) String getAvatarUrl() {
        return this.avatarUrl;
    }

    public void setName(@NotBlank(message = "Full name is required") @Size(max = 50, message = "Full name cannot exceed 50 characters") String name) {
        this.name = name;
    }

    public void setBio(@NotBlank(message = "Bio is required") String bio) {
        this.bio = bio;
    }

    public void setAvatarUrl(@Pattern(
            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg|gif))$",
            message = "Avatar must be a valid image URL (png, jpg, jpeg, gif)"
    ) String avatarUrl) {
        this.avatarUrl = avatarUrl;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof UpdateProfileDto)) return false;
        final UpdateProfileDto other = (UpdateProfileDto) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$name = this.getName();
        final Object other$name = other.getName();
        if (this$name == null ? other$name != null : !this$name.equals(other$name)) return false;
        final Object this$bio = this.getBio();
        final Object other$bio = other.getBio();
        if (this$bio == null ? other$bio != null : !this$bio.equals(other$bio)) return false;
        final Object this$avatarUrl = this.getAvatarUrl();
        final Object other$avatarUrl = other.getAvatarUrl();
        if (this$avatarUrl == null ? other$avatarUrl != null : !this$avatarUrl.equals(other$avatarUrl)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof UpdateProfileDto;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $name = this.getName();
        result = result * PRIME + ($name == null ? 43 : $name.hashCode());
        final Object $bio = this.getBio();
        result = result * PRIME + ($bio == null ? 43 : $bio.hashCode());
        final Object $avatarUrl = this.getAvatarUrl();
        result = result * PRIME + ($avatarUrl == null ? 43 : $avatarUrl.hashCode());
        return result;
    }

    public String toString() {
        return "UpdateProfileDto(name=" + this.getName() + ", bio=" + this.getBio() + ", avatarUrl=" + this.getAvatarUrl() + ")";
    }
}
