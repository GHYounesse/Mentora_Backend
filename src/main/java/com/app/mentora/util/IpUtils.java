package com.app.mentora.util;

import jakarta.servlet.http.HttpServletRequest;

public class IpUtils {
    public static String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        return (xfHeader != null) ? xfHeader.split(",")[0] : request.getRemoteAddr();
    }
    public static void simulateDelay(){
        try {
            Thread.sleep(100 + (long)(Math.random() * 100));
        } catch (InterruptedException ignored) {}
    }
}
