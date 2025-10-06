package com.app.mentora.dto.auth;

public class ChangeEmailRequest {
    private String newEmail;

    public ChangeEmailRequest() {
    }

    public String getNewEmail() {
        return this.newEmail;
    }

    public void setNewEmail(String newEmail) {
        this.newEmail = newEmail;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof ChangeEmailRequest)) return false;
        final ChangeEmailRequest other = (ChangeEmailRequest) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$newEmail = this.getNewEmail();
        final Object other$newEmail = other.getNewEmail();
        if (this$newEmail == null ? other$newEmail != null : !this$newEmail.equals(other$newEmail)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof ChangeEmailRequest;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $newEmail = this.getNewEmail();
        result = result * PRIME + ($newEmail == null ? 43 : $newEmail.hashCode());
        return result;
    }

    public String toString() {
        return "ChangeEmailRequest(newEmail=" + this.getNewEmail() + ")";
    }
}
