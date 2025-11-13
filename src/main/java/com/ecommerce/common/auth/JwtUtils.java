package com.ecommerce.common.auth;

import io.jsonwebtoken.Claims;
import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtils {

    /**
     * Create a new JWT with the user’s unique identifier.
     */
    public String generateToken(String subject) {
        return "";
    }

    /**
     * Get the user’s identity (subject) from the token.
     */
    public String extractSubject(String token) {
        return "";
    }

    /**
     * Retrieve expiration date from token claims.
     */
    public Date extractExpiration(String token) {
        return null;
    }

    /**
     * Ensure the token matches the user and isn’t expired.
     */
    public boolean isTokenValid(String token, String subject) {
        return false;
    }

    /**
     * Decode the JWT into readable claims.
     */
    public Claims parseClaims(String token) {
        return null;
    }

    /**
     * Load the secret key used for signing and verifying tokens.
     */
    public SecretKey getSigningKey() {
        return null;
    }

    /**
     * Quickly check if token time has passed.
     */
    public boolean isExpired(String token) {
        return false;
    }
}
