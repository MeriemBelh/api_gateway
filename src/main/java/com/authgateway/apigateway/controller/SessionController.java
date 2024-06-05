package com.authgateway.apigateway.controller;

import com.authgateway.apigateway.data.JwtAuthenticationResponse;
import com.authgateway.apigateway.data.Session;

import com.authgateway.apigateway.service.JwtTokenProvider;
import com.authgateway.apigateway.service.SessionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    @Autowired
    JwtTokenProvider tokenProvider;

    @Autowired
    SessionService sessionService;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    @Value("${app.refreshJwtExpirationInMs}")
    private long refreshJwtExpirationInMs;

    @PostMapping
    public ResponseEntity<JwtAuthenticationResponse> createSession(@RequestBody Session session) {

        //generate the token and send the token as a response to the monolith
        String jwt = tokenProvider.generateAccessToken(session, (long) jwtExpirationInMs);
        String refreshJwt = tokenProvider.generateAccessToken(session, refreshJwtExpirationInMs);

        session.setAccessToken(jwt);
        session.setRefreshToken(refreshJwt);

        Session savedSession = sessionService.saveSession(session);

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshJwt)
                .httpOnly(true)
                .path("/")
                .maxAge(7 * 24 * 60 * 60) // Set the expiration time as needed (e.g., 7 days)
                .build();

        // Return JWT token in response
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        // Return the access token in the response body and the refresh token in the cookie
        return ResponseEntity.ok()
                .headers(headers)
                .body(new JwtAuthenticationResponse(jwt));



    }

}