package com.app.mentora.service.limit_rate;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    @Value("${rate.limit.requests}")
    private int maxRequests;
    @Value("${rate.limit.duration-minutes}")
    private int durationMinutes;

    public Bucket resolveBucket(String key) {
        return cache.computeIfAbsent(key, k -> createBucket());
    }



    private Bucket createBucket() {
        Bandwidth limit = Bandwidth.classic(
                maxRequests,
                Refill.intervally(maxRequests, Duration.ofMinutes(durationMinutes))
        );
        return Bucket.builder().addLimit(limit).build();
    }

    public boolean tryConsume(String key) {
        Bucket bucket = resolveBucket(key);
        return bucket.tryConsume(1);
    }

    public void clearBucket(String key) {
        cache.remove(key);
    }
}