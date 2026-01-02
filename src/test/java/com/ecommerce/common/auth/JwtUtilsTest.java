package com.ecommerce.common.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JwtUtils covering token generation, parsing, validation,
 * expiration handling, and malformed or invalid tokens.
 */
class JwtUtilsTest {

    private static JwtUtils jwtUtils;
    private static SecretKey secretKey;
    private static Clock clock;

    private final String subject = "user@example.com";
    private final List<String> roles = List.of("ADMIN", "USER");

    @BeforeAll
    static void setup() throws Exception {
        // Generates a key using HmacSHA256 algorithm
        secretKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        // Simulate time at 1/1/2025
        clock = Clock.fixed(
                Instant.parse("2025-01-01T00:00:00Z"),
                ZoneId.of("UTC")
        );
        // Fresh JwtUtils instance for each test to avoid state leakage between tests
        jwtUtils = new JwtUtils(secretKey, 3600000, clock);
    }


    @Test
    void shouldGenerateValidToken() {
        String token = jwtUtils.generateToken(subject, roles);
        Claims claims = jwtUtils.parseClaims(token);
        assertTrue(jwtUtils.isTokenValid(claims, subject));
    }

    @Test
    void shouldDetectExpiredToken() {
        // Token created at 00:00, expires at 01:00
        String token = jwtUtils.generateToken(subject, roles);
        Claims claims = jwtUtils.parseClaims(token);

        // Simulate current time at 02:00
        Clock expiredClock = Clock.fixed(
                Instant.parse("2025-01-01T02:00:00Z"),
                ZoneId.of("UTC")
        );

        // JwtUtils with simulated time set to 02:00 (makes the token expired)
        JwtUtils jwtExpired = new JwtUtils(secretKey, 3600000, expiredClock);

        // Should now be considered expired
        assertTrue(jwtExpired.isExpired(claims));
    }

    @Test
    void shouldExtractSubjectFromValidToken() {
        String token = jwtUtils.generateToken(subject, roles);
        Claims claim = jwtUtils.parseClaims(token);
        assertEquals(subject, jwtUtils.extractSubject(claim));
    }

    @Test
    void shouldExtractRolesFromToken() {
        String token = jwtUtils.generateToken(subject, roles);
        Claims claim = jwtUtils.parseClaims(token);
        assertEquals(roles, jwtUtils.extractRoles(claim));
    }

    @Test
    void shouldReturnExpirationDateFromToken() {
        // Token created at 00:00, expires at 01:00
        String token = jwtUtils.generateToken(subject, roles);
        Claims claim = jwtUtils.parseClaims(token);
        Date extractedDate  = jwtUtils.extractExpiration(claim);

        // Date object set at 01:00
        Date expectedDate  = Date.from(
                Instant.parse("2025-01-01T00:00:00Z")
                        .plusMillis(3600000)
        );

        // Date objects should be equal
        assertEquals(expectedDate, extractedDate);
    }


    @Test
    void shouldThrowException_WhenTokenIsMalformed() {
        // Create a malformed token
        String malformedToken = "asdaas123sasdtrash";

        // If the token is malformed, parsing fails.
        assertThrows(JwtException.class, () -> {
            jwtUtils.parseClaims(malformedToken);
        });
    }

    @Test
    void shouldRejectToken_WhenSignatureIsInvalid() throws NoSuchAlgorithmException {
        // Create a token using the current jwtUtils instance
        String token = jwtUtils.generateToken(subject, roles);

        // Generate a new, completely different key
        SecretKey newKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        // Create a new JwtUtils with the new key
        JwtUtils jwtWithNewKey = new JwtUtils(newKey, 3600000, clock);

        // Verifying the signature fails during parsing because jwtWithNewKey
        // was created with a different key than the one used to sign the token.
        assertThrows(JwtException.class, () -> {
            jwtWithNewKey.parseClaims(token);
        });
    }

    @Test
    void shouldNotValidateToken_WhenTokenIsExpired() {
        // Token created at 00:00, expires at 01:00
        String token = jwtUtils.generateToken(subject, roles);
        Claims claims = jwtUtils.parseClaims(token);

        // Move clock ahead by 2 hours
        Clock expiredClock = Clock.fixed(
                Instant.parse("2025-01-01T02:00:00Z"),
                ZoneId.of("UTC")
        );

        // JwtUtils with simulated time set at 02:00 (makes the token expired)
        JwtUtils jwtExpired = new JwtUtils(secretKey, 3600000, expiredClock);

        // Should now be considered expired and will not be valid
        assertFalse(jwtExpired.isTokenValid(claims,subject));
    }
}