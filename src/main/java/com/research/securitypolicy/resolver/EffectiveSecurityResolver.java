package com.research.securitypolicy.resolver;

import java.util.List;

import com.research.securitypolicy.model.AuthorizationDefinition;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;

public interface EffectiveSecurityResolver {

    AuthorizationDefinition resolve(
            EndpointDefinition endpoint,
            List<RequestSecurityRule> requestRules
    );
}