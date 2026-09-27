package com.research.securitypolicy.analyzer;

import java.util.List;

import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;

public interface RequestSecurityAnalyzer {

    List<RequestSecurityRule> analyze(
            List<EndpointDefinition> endpoints
    );
}