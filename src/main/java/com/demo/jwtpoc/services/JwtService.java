package com.demo.jwtpoc.services;

import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    // Read the Base64 encoded secret from application.properties
    @Value("${jwt.secret}")
    private String secret;

    // SecretKey used to sign and verify JWT tokens
    private SecretKey secretKey;

    // This method runs after Spring injects the value of jwt.secret
    @PostConstruct
    public void init() {

        // Decode the Base64 string into the original key bytes
        byte[] keyBytes = Base64.getDecoder().decode(secret);

        // Convert the key bytes into a SecretKey object
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    // Generate a JWT token for the given username
    
    public String generateToken(String username) {

        return Jwts.builder()

                // Store the username inside the JWT subject claim
                .subject(username)

                // Set token creation time
                .issuedAt(new Date())

                // Set token expiration time
                .expiration(
                    new Date(System.currentTimeMillis() + 1000 * 60 * 60)
                )

                // Sign the token using our secret key
                .signWith(secretKey)

                // Build the final JWT string
                .compact();
    }
    
    
 // ---------- EXTRACT USERNAME ----------
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // ---------- EXTRACT EXPIRATION ----------
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // ---------- GENERIC CLAIM EXTRACTOR ----------
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    // ---------- PARSE THE TOKEN ----------FO
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)      // check the signature
                .build()
                .parseSignedClaims(token)       // throws exception if bad
                .getPayload();                  // return the payload (claims)
    }
 // ---------- VALIDATE TOKEN ----------
    public String validateToken(String token, String expectedUsername) {
        try {
            Claims claims = extractAllClaims(token);

            String username = claims.getSubject();
            if (username == null || username.isEmpty()) {
                return "INVALID: token has no subject (username)";
            }

            if (!username.equals(expectedUsername)) {
                return "INVALID: token belongs to '" + username
                        + "' but expected '" + expectedUsername + "'";
            }

            Date expiration = claims.getExpiration();
            if (expiration == null) {
                return "INVALID: token has no expiration";
            }
            if (expiration.before(new Date())) {
                return "INVALID: token expired at " + expiration;
            }

            return "VALID";

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            return "INVALID: token expired (" + e.getMessage() + ")";
        } catch (io.jsonwebtoken.security.SignatureException e) {
            return "INVALID: signature does not match our secret";
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            return "INVALID: token is malformed";
        } catch (io.jsonwebtoken.JwtException e) {
            return "INVALID: " + e.getMessage();
        } catch (Exception e) {
            return "INVALID: unexpected error - " + e.getMessage();
        }
    }
}