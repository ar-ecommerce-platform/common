package com.ecommerce.common.auth;

import io.jsonwebtoken.Claims;
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

class JwtUtilsTest {

    private static JwtUtils jwtUtils;
    private static SecretKey secretKey;
    private static Clock clock;

    private final String subject = "user@example.com";
    private final List<String> roles = List.of("ADMIN", "USER");

    @BeforeAll
    static void setup() throws Exception {
        secretKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        clock = Clock.fixed(
                Instant.parse("2025-01-01T00:00:00Z"),
                ZoneId.of("UTC")
        );
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
        String token = jwtUtils.generateToken(subject, roles);
        Claims claim = jwtUtils.parseClaims(token);
        Date actualDate = jwtUtils.extractExpiration(claim);
        Date expectedDate  = Date.from(
                Instant.parse("2025-01-01T00:00:00Z")
                        .plusMillis(3600000)
        );
        assertEquals(actualDate , expectedDate);
    }

    @Test
    void shouldFailValidation_WhenTokenIsMalformed() {
        String malformedToken = "asdaas123sasdtrash";
        Claims claims = jwtUtils.parseClaims(malformedToken);
        assertFalse(jwtUtils.isTokenValid(claims,subject));
    }

    @Test
    void shouldFailValidation_WhenSignatureIsInvalid() throws NoSuchAlgorithmException {
        String token = jwtUtils.generateToken(subject, roles);
        Claims claim = jwtUtils.parseClaims(token);

        // Generate a completely different key
        SecretKey invalidKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        // JwtUtils with wrong key
        JwtUtils jwtWithWrongKey = new JwtUtils(invalidKey, 3600000, clock);
        assertFalse(jwtWithWrongKey.isTokenValid(claim, subject));
    }

    @Test
    void shouldNotValidateToken_WhenTokenIsExpired() {
        String token = jwtUtils.generateToken(subject, roles);
        Claims claims = jwtUtils.parseClaims(token);
        // Move clock ahead by 2 hours
        Clock expiredClock = Clock.fixed(
                Instant.parse("2025-01-01T02:00:00Z"),
                ZoneId.of("UTC")
        );
        JwtUtils jwtExpired = new JwtUtils(secretKey, 3600000, expiredClock);
        assertFalse(jwtExpired.isTokenValid(claims,subject));
    }

}