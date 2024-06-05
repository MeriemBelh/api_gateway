package com.authgateway.apigateway.repository;

import com.authgateway.apigateway.data.Session;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session, Long> {

    Session findBySessionId(String sessionId);
}