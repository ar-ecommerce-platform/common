package com.ecommerce.common.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtils {

    private final SecretKey jwtSigningKey;
    private final long expirationMs;

    public JwtUtils(SecretKey jwtSigningKey, long expirationMs) {
        this.jwtSigningKey = jwtSigningKey;
        this.expirationMs = expirationMs;
    }

    /**
     * Create a new JWT Token with the user’s unique identifier.
     *
     * @param subject The user's email
     * @return The signed JWT token
     */
    public String generateToken(String subject) {
        return Jwts.builder()
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(jwtSigningKey)
                .compact();
    }

    /**
     *  Get the user identity (subject) from a token.
     *
     * @param token The JWT Token
     * @return The subject stored in the token
     * */
    public String extractSubject(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Retrieve expiration date from token claims.
     */
    public Date extractExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    /**
     * Ensure the token matches the user and isn’t expired.
     */
    public boolean isTokenValid(String token, String subject) {
        String extracted = extractSubject(token);
        return (extracted.equals(subject) && !isExpired(token));
    }

    /**
     * Decode the JWT into readable claims.
     */
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(jwtSigningKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Quickly check if token time has passed.
     */
    public boolean isExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
