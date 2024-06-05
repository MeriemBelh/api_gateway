package com.authgateway.apigateway.service;

import com.authgateway.apigateway.data.Session;
import com.authgateway.apigateway.repository.SessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SessionService {

    @Autowired
    SessionRepository sessionRepository;

    public Session saveSession(Session session) {
        return sessionRepository.save(session);
    }
}
