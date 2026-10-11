package com.demo.jwtpoc.config;

import com.demo.jwtpoc.filter.JwtAuthFilter;

import jakarta.servlet.Filter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// Tells Spring that this class contains bean definitions
// (methods annotated with @Bean will be managed by the Spring container)
@Configuration

// Enables Spring Security's web support
// Without this, the SecurityFilterChain bean may not be picked up correctly
@EnableWebSecurity
public class SecurityConfig {

    // Our custom JWT filter that reads the token from each request
    // and populates the SecurityContext if the token is valid
    private final JwtAuthFilter jwtAuthFilter;

    // Constructor injection:
    // Spring sees that SecurityConfig needs a JwtAuthFilter,
    // finds the @Component-annotated JwtAuthFilter bean,
    // and injects it here.
    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    // The main security configuration bean.
    // Defines which endpoints are public, which require authentication,
    // and where our JWT filter sits in the filter chain.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Explicitly treat our filter as jakarta.servlet.Filter.
        // This helps the compiler match the correct overload of
        // addFilterBefore(Filter, Class<? extends Filter>).
        Filter jwtFilter = (Filter) jwtAuthFilter;

        http

            // CSRF protection is meant for browser form-based apps
            // that rely on session cookies. For a stateless REST API
            // using JWTs, it is not needed, so we disable it.
            .csrf(csrf -> csrf.disable())

            // Define URL access rules
            .authorizeHttpRequests(auth -> auth

                // /auth/register and /auth/login must be accessible
                // without any token — otherwise a new user could never
                // register or log in.
                .requestMatchers("/auth/register", "/auth/login").permitAll()

                // /test/generate is kept public temporarily so we can
                // create tokens while testing. We will lock it down later.
                .requestMatchers("/test/generate").permitAll()

                // Every other endpoint requires a valid authenticated user
                // (i.e. a valid JWT must be present in the request)
                .anyRequest().authenticated()
            )

            // Tell Spring Security NOT to create or use HTTP sessions.
            // Each request must prove its identity on its own via the JWT.
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Register our JWT filter BEFORE Spring's default
            // UsernamePasswordAuthenticationFilter.
            // This way, if a valid JWT is present, the SecurityContext
            // is populated before Spring's own authentication logic runs.
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        // Build the configured filter chain and hand it to Spring
        return http.build();
    }

    // The reason we create this bean is that Spring Security provides
    // the PasswordEncoder abstraction, and we configure which implementation
    // we want to use — here, BCrypt — and let Spring manage it through
    // dependency injection.
    @Bean
    public PasswordEncoder passwordEncoder() {

        // BCryptPasswordEncoder is the implementation of the
        // PasswordEncoder interface used to securely hash passwords.
        // It uses BCrypt hashing with a random salt, and the resulting
        // hash is a one-way value that cannot be reversed.
        return new BCryptPasswordEncoder();
    }
}