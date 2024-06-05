package com.authgateway.apigateway.controller;

import com.authgateway.apigateway.data.JwtUtil;
import com.authgateway.apigateway.data.Session;
import com.authgateway.apigateway.service.JwtTokenProvider;
import com.authgateway.apigateway.service.SessionService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/authorisations")
public class AuthorisationController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @GetMapping
    public ResponseEntity<String> getAuthorisation(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        // Check if user has the required role
        String token = extractToken(authorizationHeader);

        if (token == null) {
            return ResponseEntity.badRequest().body("Invalid token");
        }

        // Verify the token
        if (!jwtTokenProvider.verifyToken(token)) {
            return ResponseEntity.badRequest().body("Token verification failed");
        }

        // Extract user details from the token
        String role = jwtTokenProvider.extractRoleClaim(token);
        if (role == null) {
            return ResponseEntity.badRequest().body("Failed to extract user details");
        }

        // Check user role
        if (!jwtTokenProvider.hasRequiredRole(role, token)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("User does not have the required role");
        }

        return ResponseEntity.ok("Token is verified and user has the correct role");

    }

    private String extractToken(String authorizationHeader) {
        // Remove "Bearer " prefix to extract the token
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        Map<String, String> response = jwtTokenProvider.refreshAccessToken(refreshToken);



        if (response != null) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(500).body(null);
        }
    }

    @PostMapping("/isExpired")
    public ResponseEntity<Map<String, Boolean>> isTokenExpired(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        Map<String, Boolean> response = new HashMap<>();
        response.put("isExpired", jwtTokenProvider.isTokenExpired(token));
        return ResponseEntity.ok(response);
    }



}
