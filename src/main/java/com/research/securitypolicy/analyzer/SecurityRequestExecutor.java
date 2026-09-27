package com.research.securitypolicy.analyzer;

import java.util.List;

import com.research.securitypolicy.model.EndpointDefinition;

public interface SecurityRequestExecutor {

    boolean isAllowedAnonymous(
            EndpointDefinition endpoint
    );

    boolean isAllowedAuthenticated(
            EndpointDefinition endpoint
    );

    boolean isAllowedWithRoles(
            EndpointDefinition endpoint,
            List<String> roles
    );
}