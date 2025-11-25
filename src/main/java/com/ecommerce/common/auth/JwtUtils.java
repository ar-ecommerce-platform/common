package com.ecommerce.common.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

public class JwtUtils {

    private static final String CLAIM_ROLES = "roles";
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
                .claim(CLAIM_ROLES, roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(jwtSigningKey, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Removes "Bearer " from tokens that come from the Authorization header.
     *
     * @param token The token coming from the client.
     * @return The token without the "Bearer " prefix.
     */
    private String cleanToken(String token) {
        if (token == null){
            return null;
        }
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
        token = cleanToken(token);
        if (token == null || token.isBlank()) {
            throw new JwtException("Token is null or empty");
        }
        return Jwts.parser()
                .verifyWith(jwtSigningKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extracts the subject (usually the user's email or ID) from the claims.
     *
     * @param claims the already-parsed JWT claims
     * @return the subject stored in the token (never null if token is valid)
     */
    public String extractSubject(Claims claims) {
        return claims.getSubject();
    }

    /**
     * Extracts the expiration date from the claims.
     *
     * @param claims the already-parsed JWT claims
     * @return the expiration date of the token
     */
    public Date extractExpiration(Claims claims) {
        return claims.getExpiration();
    }

    /**
     * Determines whether a token is expired.
     *
     * @param claims the already-parsed JWT claims
     * @return true if the current time is after the expiration time
     */
    public boolean isExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    /**
     *  Validates a token by its claims, ensuring:
     *      Subject matches the expected user
     *      Token is not expired
     *
     * @param claims the already-parsed JWT claims
     * @param expectedSubject The subject you expect.
     * @return true if the token is valid, false otherwise.
     */
    public boolean isTokenValid(Claims claims, String expectedSubject) {
        return expectedSubject.equals(claims.getSubject())
                && claims.getExpiration().after(new Date());
    }

    /**
     * Extracts the list of roles stored inside the JWT claims.
     *
     * @param claims Already parsed JWT claims
     * @return A list of roles. Returns an empty list if none are found.
     */

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(Claims claims) {
        Object rolesObj = claims.get(CLAIM_ROLES);
        if (rolesObj instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    /**
     * Checks if the JWT claims has a specific role.
     *
     * @param claims Already parsed JWT claims
     * @param role  The role you want to verify.
     * @return true if the user has the role, false otherwise.
     */
    public boolean hasRole(Claims claims, String role) {
        Object rolesObj = claims.get(CLAIM_ROLES);
        if (rolesObj instanceof List<?> list) {
            return list.stream().anyMatch(r -> r.toString().equals(role));
        }
        return false;
    }
}
