package com.app.mentora.security;

import com.app.mentora.service.auth.CustomUserDetailsService;
import com.app.mentora.service.token.TokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

@Component
public class JwtAuthentificationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthentificationFilter.class);
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;

    public JwtAuthentificationFilter(JwtUtil jwtUtil,
                                   CustomUserDetailsService userDetailsService,
                                   TokenBlacklistService blacklistService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.blacklistService = blacklistService;
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = extractTokenFromRequest(request);

            if (token != null) {
                // Step 1: Validate token structure and signature
                String username = jwtUtil.getUsernameFromToken(token);

                // Step 2: Get JWT ID for blacklist check
                String jti = jwtUtil.getJtiFromToken(token);

                // Step 3: Get Roles from token
                List<String> roles=jwtUtil.getRolesFromToken(token);
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                // Step 3: Check if token is blacklisted
                if (blacklistService.isBlacklisted(jti)) {
                    log.warn("Attempted to use blacklisted token: {}", jti);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\":\"Token has been revoked\"}");
                    return;
                }

                // Step 4: Check if user exists and token is valid
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    // Step 5: Check if all user tokens are blacklisted (password change, etc.)
                    var user = userDetailsService.getUserByEmail(username);
                    if (blacklistService.areAllUserTokensBlacklisted(user.getId())) {
                        log.warn("Attempted to use token for user with all tokens revoked: {}", username);
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("{\"error\":\"All tokens revoked. Please login again.\"}");
                        return;
                    }

                    // Step 6: Final validation
                    if (jwtUtil.validateToken(token, username)) {
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails,
                                        null,
                                        authorities
                                );
                        authentication.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                        );
                        SecurityContextHolder.getContext().setAuthentication(authentication);

                        log.debug("JWT authentication successful for user: {}", username);
                    } else {
                        log.warn("JWT validation failed for user: {}", username);
                    }
                }
            }
        } catch (JwtUtil.JwtValidationException e) {
            log.error("JWT validation error: {}", e.getMessage());
            // Don't set authentication, let it proceed as unauthenticated
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);

    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
