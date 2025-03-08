package com.School.API.Gateway.security;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.charset.StandardCharsets;

@Component
public class JwtUtil {  //we only need to validate the token hence no need for the other methods as in the auth service

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expirationMs}")
    private int jwtExpirationMs;

    public boolean validateJwtToken(String authToken) {
        try {
            String token = authToken.replace("Bearer ", "").trim();
            logger.info("Validating token: {}", token);
            Jwts.parserBuilder()
                    .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token);
            logger.info("Token validated successfully");
            return true;
        } catch (Exception e) {
            logger.error("JWT validation failed: {}",e.getMessage());
            System.err.println("JWT validation failed: " + e.getMessage());
            return false;
        }
    }
}