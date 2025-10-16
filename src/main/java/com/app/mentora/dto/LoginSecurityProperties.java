package com.app.mentora.dto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class LoginSecurityProperties {

    @Value("${user.max_failed_attempts}")
    private int maxFailedAttempts;

    @Value("${user.lock_time_duration}")
    private long lockTimeDuration;

    public int getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    public long getLockTimeDuration() {
        return lockTimeDuration;
    }
}

