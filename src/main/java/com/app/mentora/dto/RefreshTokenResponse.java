package com.app.mentora.dto;

import com.app.mentora.model.token.RefreshToken;



public class RefreshTokenResponse {
    private RefreshToken refreshToken;
    private String rawToken;

    public RefreshTokenResponse() {

    }
    public RefreshTokenResponse(RefreshToken refreshToken, String rawToken) {
        this.refreshToken = refreshToken;
        this.rawToken = rawToken;
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public String getRawToken() {
        return rawToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void setRawToken(String rawToken) {
        this.rawToken = rawToken;
    }
}

