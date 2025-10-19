package com.app.mentora.config.auth;

import org.springframework.beans.factory.annotation.Value;
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

import com.app.mentora.security.JwtAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

@Configuration //this class  is a Spring configuration class
@EnableWebSecurity //Enables Spring Security’s web support
@EnableMethodSecurity //Allows @PreAuthorize/@Secured at method level
@EnableJpaAuditing //Auditing support for created/updated timestamps
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtFilter) { this.jwtFilter = jwtFilter; }

    private static final String[] PUBLIC_ENDPOINTS = {
            "/api/v1/auth/**",
            "/api/v1/account/verify-email-change",
            "/api/v1/content/public/**"
    };
    @Value("${cors.allowed.origins}")
    private String[] allowedOrigins;

    @Bean
    public SecurityFilterChain filterChain(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
//                        csrf -> csrf
//                                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                                // Exclude only login, refresh, or public endpoints
//                                .ignoringRequestMatchers("/api/v1/auth/**")
//
//                )
                .cors(Customizer.withDefaults())//Enables the CorsConfigurationSource bean
                .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        // Restricted routes
                        .requestMatchers("/api/v1/content/premium/**").hasAnyRole("PREMIUM", "ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        // Catch-all for others
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
        //http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

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

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // Allow only trusted origins
        config.setAllowedOrigins(Arrays.asList(allowedOrigins));

        //Allowed HTTP methods
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // Allowed headers
        config.setAllowedHeaders(List.of(
                "Authorization", "Content-Type", "X-XSRF-TOKEN", "Accept"
        ));

        //  Allow credentials (cookies, auth headers)
        config.setAllowCredentials(true);

        // Cache the preflight response for 1 hour
        config.setMaxAge(Duration.ofHours(1));

        // Apply this config to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);

        return source;
    }

}