package com.demo.jwtpoc.filter;

import com.demo.jwtpoc.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Read the Authorization header
        String authHeader = request.getHeader("Authorization");

        // 2. If missing or doesn't start with "Bearer " → skip
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Extract the token (everything after "Bearer ") "Bearer " is 7 characters (B-e-a-r-e-r-space).
        String token = authHeader.substring(7);

        String username;
        try {
            username = jwtService.extractUsername(token);
        } catch (Exception e) {
            // token is garbage / tampered / expired in a way that breaks parsing
            filterChain.doFilter(request, response);
            return;
        }

        // 4. Only proceed if we got a username AND no auth is set yet
        if (username != null &&
            SecurityContextHolder.getContext().getAuthentication() == null) {

            // 5. Validate the token using the method we already built
            String result = jwtService.validateToken(token, username);

            if ("VALID".equals(result)) {

                // 6. Create an Authentication object and put it in context
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                username,           // principal (who)
                                null,               // credentials (not needed)
                                Collections.emptyList()  // authorities (roles)
                        );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            // if INVALID → do nothing → request stays anonymous
        }

        // 7. Continue the chain regardless of what happened above
        filterChain.doFilter(request, response);
    }
}