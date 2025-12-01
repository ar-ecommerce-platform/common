package com.ecommerce.common.auth;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtUtilsTest {

    private JwtUtils jwtUtils;
    private SecretKey secretKey;
    private Clock clock;

    private final String subject = "user@example.com";
    private final List<String> roles = List.of("ADMIN", "USER");

    @BeforeEach
    void setup () throws Exception {
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
        String token = jwtUtils.generateToken(subject, roles);
        Claims claims = jwtUtils.parseClaims(token);
        // Move clock ahead by 2 hours
        Clock expiredClock = Clock.fixed(
                Instant.parse("2025-01-01T02:00:00Z"),
                ZoneId.of("UTC")
        );
        JwtUtils jwtExpired = new JwtUtils(secretKey, 3600000, expiredClock);
        assertTrue(jwtExpired.isExpired(claims));
    }

    @Test
    void shouldExtractSubjectFromValidToken() {
        String token = jwtUtils.generateToken(subject, roles);
        Claims claim = jwtUtils.parseClaims(token);
        assertEquals(subject, jwtUtils.extractSubject(claim));
    }

    @Test
    void shouldExtractRolesFromToken() {}

    @Test
    void shouldReturnExpirationDateFromToken() {}

    @Test
    void shouldFailValidation_WhenTokenIsMalformed() {}

    @Test
    void shouldFailValidation_WhenSignatureIsInvalid() {}

    @Test
    void shouldValidateToken_WhenTokenIsValid() {}

    @Test
    void shouldNotValidateToken_WhenTokenIsExpired() {}

}