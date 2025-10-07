package com.app.mentora.security;

import com.app.mentora.service.auth.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.util.StringUtils;
@Component
public class JwtAuthentificationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    public JwtAuthentificationFilter(JwtUtil jwtUtil, CustomUserDetailsService uds) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = uds;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        System.out.println(">>> Incoming request: " + request.getRequestURI());
        System.out.println(">>> Authorization header: " + header);

        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            System.out.println(">>> Extracted JWT: " + token);
            if (jwtUtil.validateToken(token)) {
                String username = jwtUtil.getUsernameFromToken(token);
                System.out.println(">>> Username from JWT: " + username);
                List<String> roles = jwtUtil.getRolesFromToken(token);
                System.out.println(">>> Roles from JWT: " + roles);
                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new) // keep ROLE_ prefix
                        .collect(Collectors.toList());
                var auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
                System.out.println(">>> Authorities in SecurityContext: " + SecurityContextHolder.getContext().getAuthentication().getAuthorities());
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

//                var auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//                SecurityContextHolder.getContext().setAuthentication(auth);
            } else {
            System.out.println(">>> JWT is invalid!");
            }
        }
        else {
        System.out.println(">>> No Authorization header or not Bearer");
    }
        filterChain.doFilter(request, response);

    }
}
