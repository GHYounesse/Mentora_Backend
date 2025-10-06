package com.app.mentora.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class SignupUserDto {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters")
    private String password;

    public SignupUserDto() {
    }

    public @NotBlank(message = "Email is required") @Email(message = "Invalid email format") String getEmail() {
        return this.email;
    }

    public @NotBlank(message = "Password is required") @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters") String getPassword() {
        return this.password;
    }

    public void setEmail(@NotBlank(message = "Email is required") @Email(message = "Invalid email format") String email) {
        this.email = email;
    }

    public void setPassword(@NotBlank(message = "Password is required") @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters") String password) {
        this.password = password;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof SignupUserDto)) return false;
        final SignupUserDto other = (SignupUserDto) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$email = this.getEmail();
        final Object other$email = other.getEmail();
        if (this$email == null ? other$email != null : !this$email.equals(other$email)) return false;
        final Object this$password = this.getPassword();
        final Object other$password = other.getPassword();
        if (this$password == null ? other$password != null : !this$password.equals(other$password)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof SignupUserDto;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $email = this.getEmail();
        result = result * PRIME + ($email == null ? 43 : $email.hashCode());
        final Object $password = this.getPassword();
        result = result * PRIME + ($password == null ? 43 : $password.hashCode());
        return result;
    }

    public String toString() {
        return "SignupUserDto(email=" + this.getEmail() + ", password=" + this.getPassword() + ")";
    }

//    @NotBlank(message = "Full name is required")
//    @Size(max = 50, message = "Full name cannot exceed 50 characters")
//    private String fullName;
//
//    @Pattern(
//            regexp = "^(https?:\\/\\/.*\\.(?:png|jpg|jpeg|gif))$",
//            message = "Avatar must be a valid image URL (png, jpg, jpeg, gif)"
//    )
//    private String avatarUrl;


}
