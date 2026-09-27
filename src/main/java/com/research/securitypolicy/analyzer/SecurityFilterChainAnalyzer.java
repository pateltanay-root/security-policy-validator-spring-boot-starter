package com.research.securitypolicy.analyzer;

import java.util.List;

import org.springframework.security.web.FilterChainProxy;
import jakarta.servlet.Filter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;

public class SecurityFilterChainAnalyzer
        implements RequestSecurityAnalyzer {

    private final FilterChainProxy filterChainProxy;

    public SecurityFilterChainAnalyzer(
            FilterChainProxy filterChainProxy) {

        this.filterChainProxy = filterChainProxy;
    }
    
    public AuthorizationFilter getAuthorizationFilter() {

        for (SecurityFilterChain chain :
                filterChainProxy.getFilterChains()) {

            for (jakarta.servlet.Filter filter :
                    chain.getFilters()) {

                if (filter instanceof AuthorizationFilter authorizationFilter) {
                    return authorizationFilter;
                }
            }
        }

        return null;
    }

    @Override
    public List<RequestSecurityRule> analyze(
            List<EndpointDefinition> endpoints) {

        /*
         * We deliberately do not extract matcher → role
         * mappings yet because Spring Security does not
         * expose those internal mappings through a stable
         * public enumeration API.
         *
         * This class currently verifies that request-level
         * authorization infrastructure exists.
         */
        return List.of();
    }

    public boolean hasAuthorizationFilter() {

        for (SecurityFilterChain chain :
                filterChainProxy.getFilterChains()) {

            boolean found =
                    chain.getFilters()
                            .stream()
                            .anyMatch(
                                    AuthorizationFilter.class::isInstance
                            );

            if (found) {
                return true;
            }
        }

        return false;
    }

    public int getSecurityFilterChainCount() {

        return filterChainProxy
                .getFilterChains()
                .size();
    }
}