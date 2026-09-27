package com.research.securitypolicy.analyzer;

import jakarta.servlet.http.HttpServletRequest;

import com.research.securitypolicy.model.EndpointDefinition;

public interface AuthorizationRequestFactory {

    HttpServletRequest create(
            EndpointDefinition endpoint
    );
}