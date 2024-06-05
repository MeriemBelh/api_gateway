package com.authgateway.apigateway.service;

import com.authgateway.apigateway.data.Session;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    @Value("${app.jwtSecret}")
    private String jwtSecretKey;


    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    @Value("${app.refreshJwtExpirationInMs}")
    private long refreshJwtExpirationInMs;

    public String generateAccessToken(Session session, Long expiration) {

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setSubject(session.getSessionId())
                .claim("name", session.getUsername())
                .claim("roles", session.getRole())
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecretKey)
                .compact();
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
    }
    public Map<String, String> refreshAccessToken(String refreshToken) {
        try {
            Claims claims = extractAllClaims(refreshToken);

            String sessionId = claims.getSubject();
            String name = claims.get("name", String.class);
            String roles = claims.get("roles", String.class);

            Date now = new Date();
            Date expiration = new Date(now.getTime() + jwtExpirationInMs); // 1 hour validity

            String newAccessToken = Jwts.builder()
                    .setSubject(sessionId)
                    .claim("name", name)
                    .claim("roles", roles)
                    .setIssuedAt(now)
                    .setExpiration(expiration)
                    .signWith(SignatureAlgorithm.HS512, jwtSecretKey)
                    .compact();

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", newAccessToken);

            return tokens;
        } catch (Exception e) {
            // Log the exception
            throw e;
        }
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey)))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractRoleClaim(String token) {
        final Claims claims = extractAllClaims(token);
        return (String) claims.get("roles");
    }

    public boolean verifyToken(String token) {
        try {
            // Parse the token and extract its claims

            Claims claims = extractAllClaims(token);


            // Check if the token has expired
            // Note: You can customize the behavior for expired tokens
            if (claims.getExpiration().before(new Date())) {

                return false;
            }

            // Token is valid
            return true;
        } catch (Exception e) {
            // Token verification failed
            return false;
        }
    }

    public Boolean hasRequiredRole(String role, String token){
        String receivedRole = extractRoleClaim(token);
        return receivedRole.equals(role);

    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return true; // Treat token as expired if any exception occurs
        }
    }


}
