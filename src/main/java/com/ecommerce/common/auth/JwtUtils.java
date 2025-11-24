package com.ecommerce.common.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

public class JwtUtils {

    private final SecretKey jwtSigningKey;
    private final long expirationMs;

    /**
     * Basic constructor for JwtUtils.
     *
     * @param jwtSigningKey The secret key used to sign and verify tokens.
     * @param expirationMs How long the token should be valid for (in ms).
     */
    public JwtUtils(SecretKey jwtSigningKey, long expirationMs) {
        this.jwtSigningKey = jwtSigningKey;
        this.expirationMs = expirationMs;
    }

    /**
     * Creates a new JWT token for the user.
     *
     * @param subject The user's email (or whatever ID you’re using).
     * @param roles   The list of roles the user has.
     * @return A signed JWT token as a string.
     */
    public String generateToken(String subject, List<String> roles) {
        return Jwts.builder()
                .subject(subject)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(jwtSigningKey)
                .compact();
    }

    /**
     * Removes "Bearer " from tokens that come from the Authorization header.
     *
     * @param token The token coming from the client.
     * @return The token without the "Bearer " prefix.
     */
    private String cleanToken(String token) {
        if (token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return token;
    }

    /**
     * Parses the JWT and returns the claims inside it.
     *
     * @param token The JWT string.
     * @return The token's claims.
     */
    public Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(jwtSigningKey)
                    .build()
                    .parseSignedClaims(cleanToken(token))
                    .getPayload();
        } catch (JwtException e) {
            throw new RuntimeException(e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Gets the subject (user ID/email) from the token.
     *
     * @param token The JWT string.
     * @return The subject stored inside the token.
     */
    public String extractSubject(String token) {
        Claims claims = parseClaims(token);
        return (claims != null) ? claims.getSubject() : null;
    }

    /**
     * Gets the expiration date from the token.
     *
     * @param token The JWT string.
     * @return The expiration date.
     */
    public Date extractExpiration(String token) {
        Claims claims = parseClaims(token);
        return (claims != null) ? claims.getExpiration() : null;
    }

    /**
     * Checks if the token is expired.
     *
     * @param token The JWT string.
     * @return true if expired, false if still valid.
     */
    public boolean isExpired(String token) {
        Date expiration = extractExpiration(token);
        return expiration == null || expiration.before(new Date());
    }

    /**
     * Checks if the token belongs to the correct user and isn’t expired.
     *
     * @param token The JWT string.
     * @param expectedSubject The subject you expect.
     * @return true if the token is valid, false otherwise.
     */
    public boolean isTokenValid(String token, String expectedSubject) {
        Claims claims = parseClaims(token);
        if (claims == null) {
            return false;
        }
        return expectedSubject.equals(claims.getSubject()) && claims.getExpiration().after(new Date());
    }

    /**
     * Extracts the list of roles stored inside the token.
     *
     * @param token The JWT string.
     * @return A list of roles. Returns an empty list if none are found.
     */

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Claims claims = parseClaims(token);
        if (claims == null) {
            return List.of();
        }

        Object rolesObj = claims.get("roles");
        if (rolesObj == null) {
            return List.of();
        }

        // Case 1: already List<String>
        if (rolesObj instanceof List<?> list) {
            // convert each element to string just in case
            return list.stream().map(String::valueOf).toList();
        }

        return List.of();
    }

    /**
     * Checks if the token has a specific role.
     *
     * @param token The JWT string.
     * @param role  The role you want to verify.
     * @return true if the user has the role, false otherwise.
     */
    public boolean hasRole(String token, String role) {
        return extractRoles(token).contains(role);
    }
}
