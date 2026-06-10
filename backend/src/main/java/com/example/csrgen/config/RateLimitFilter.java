package com.example.csrgen.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dependency-free per-IP fixed-window rate limiter for the expensive POST endpoints
 * (key generation / match / history writes). Returns 429 with the standard error body.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RateLimitFilter extends OncePerRequestFilter {

    @Value("${app.ratelimit.capacity:120}")
    private int capacity;

    @Value("${app.ratelimit.window-ms:60000}")
    private long windowMs;

    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    private static final class Window {
        volatile long start;
        final AtomicInteger count = new AtomicInteger();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        if (!"POST".equalsIgnoreCase(req.getMethod())) {
            return true;
        }
        // getRequestURI includes the /api context-path and is stable under MockMvc + prod.
        String p = req.getRequestURI();
        return !(p.contains("/csr/generate") || p.contains("/csr/match") || p.contains("/csr/history"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String ip = clientIp(req);
        long now = System.currentTimeMillis();
        Window w = windows.computeIfAbsent(ip, k -> {
            Window nw = new Window();
            nw.start = now;
            return nw;
        });
        synchronized (w) {
            if (now - w.start >= windowMs) {
                w.start = now;
                w.count.set(0);
            }
        }
        if (w.count.incrementAndGet() > capacity) {
            res.setStatus(429);
            res.setContentType("application/json");
            res.getWriter().write(
                    "{\"error\":{\"message\":\"Rate limit exceeded. Please slow down and try again shortly.\"}}");
            return;
        }
        chain.doFilter(req, res);
    }

    private String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }
}
