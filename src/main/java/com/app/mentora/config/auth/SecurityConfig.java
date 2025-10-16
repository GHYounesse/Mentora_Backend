package com.app.mentora.config.auth;

import org.springframework.context.annotation.*;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.app.mentora.security.JwtAuthentificationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableJpaAuditing
public class SecurityConfig {
    private final JwtAuthentificationFilter jwtFilter;

    public SecurityConfig(JwtAuthentificationFilter jwtFilter) { this.jwtFilter = jwtFilter; }

    @Bean
    public SecurityFilterChain filterChain(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        http.csrf(//csrf -> csrf.disable()
                        csrf -> csrf
                                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                                // Exclude only login, refresh, or public endpoints
                                .ignoringRequestMatchers("/api/v1/auth/login", "/api/v1/auth/refresh","/api/v1/auth/register")

                )
                .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**","/api/v1/account/verify-email-change").permitAll()
                        .requestMatchers("/api/v1/content/public/**").permitAll()
                        .requestMatchers("/api/v1/content/premium/**").hasAnyRole("PREMIUM", "ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .headers(headers -> headers
                        // Prevent MIME sniffing
                        .contentTypeOptions(Customizer.withDefaults())

                        // Prevent clickjacking
                        .frameOptions(frame -> frame.deny())

                        // Strict-Transport-Security (HSTS)
//                        .httpStrictTransportSecurity(hsts -> hsts
//                                .maxAgeInSeconds(31536000)
//                                .includeSubDomains(true)
//                        )
                        .httpStrictTransportSecurity(hsts -> hsts.disable())

                        // Content-Security-Policy (CSP)
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives(
//                                        "default-src 'self'; " +
//                                                "script-src 'self'; " +
//                                                "style-src 'self' 'unsafe-inline'; " +
//                                                "img-src 'self' data:; " +
//                                                "object-src 'none'; " +
//                                                "frame-ancestors 'none'; " +
//                                                "base-uri 'self';"
                                        "default-src 'self' http://localhost:4200; " +
                                                "script-src 'self' http://localhost:4200 'unsafe-inline' 'unsafe-eval'; " +
                                                "style-src 'self' http://localhost:4200 'unsafe-inline'; " +
                                                "connect-src 'self' http://localhost:4200 http://localhost:8080; " +
                                                "img-src 'self' data: http://localhost:4200;"
                                )
                        )

                        // Referrer-Policy
                        .referrerPolicy(referrer -> referrer
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)
                        )


                        .addHeaderWriter((request, response) ->
                                response.setHeader("Permissions-Policy",
                                        "geolocation=(), microphone=(), camera=(), fullscreen=(self)")
                        )

                        // Add Cache-Control manually for sensitive endpoints (optional)
                        .cacheControl(Customizer.withDefaults())
                );



        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        // for H2 console (dev only)
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}