package com.authgateway.apigateway.data;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;


public class JwtUtil {

    private String Authorization;

    public JwtUtil(String authorization){
        this.Authorization = authorization;
    }


    public String getAuthorization() {
        return Authorization;
    }

    public void setAuthorization(String authorization) {
        Authorization = authorization;
    }


}
