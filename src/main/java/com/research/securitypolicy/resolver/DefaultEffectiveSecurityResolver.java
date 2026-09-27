package com.research.securitypolicy.resolver;

import java.util.List;

import org.springframework.util.AntPathMatcher;

import com.research.securitypolicy.model.AuthorizationDefinition;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;
import com.research.securitypolicy.model.SecuritySource;

public class DefaultEffectiveSecurityResolver
        implements EffectiveSecurityResolver {

    private final AntPathMatcher pathMatcher =
            new AntPathMatcher();

    @Override
    public AuthorizationDefinition resolve(
            EndpointDefinition endpoint,
            List<RequestSecurityRule> requestRules) {

        if (endpoint == null) {
            throw new IllegalArgumentException(
                    "Endpoint must not be null"
            );
        }

        AuthorizationDefinition methodSecurity =
                endpoint.getAuthorization();

        /*
         * Method-level security exists.
         *
         * Keep the method rule as the effective
         * authorization for this phase.
         */
        if (methodSecurity != null
                && methodSecurity.getSecuritySource()
                != SecuritySource.NONE) {

            return copy(methodSecurity);
        }


        /*
         * No method-level security.
         *
         * Look for a matching request-level rule.
         */
        RequestSecurityRule matchedRule =
                findMatchingRule(
                        endpoint,
                        requestRules
                );

        if (matchedRule != null) {

            return new AuthorizationDefinition(
                    matchedRule.getAccessType(),
                    SecuritySource.SECURITY_FILTER_CHAIN,
                    matchedRule.getRoles(),
                    matchedRule.getRawRule()
            );
        }


        /*
         * No request-level rule was discovered.
         *
         * Preserve the scanner result.
         */
        if (methodSecurity != null) {
            return copy(methodSecurity);
        }

        return null;
    }


    private RequestSecurityRule findMatchingRule(
            EndpointDefinition endpoint,
            List<RequestSecurityRule> requestRules) {

        if (requestRules == null
                || requestRules.isEmpty()) {

            return null;
        }

        for (RequestSecurityRule rule : requestRules) {

            if (rule == null) {
                continue;
            }

            if (!methodMatches(
                    endpoint,
                    rule)) {

                continue;
            }

            if (!pathMatches(
                    endpoint,
                    rule)) {

                continue;
            }

            /*
             * First matching rule wins.
             *
             * This lets us preserve ordered
             * request-security rules later.
             */
            return rule;
        }

        return null;
    }


    private boolean methodMatches(
            EndpointDefinition endpoint,
            RequestSecurityRule rule) {

        /*
         * Null/blank method means:
         * rule applies to every HTTP method.
         */
        if (rule.getHttpMethod() == null
                || rule.getHttpMethod().isBlank()) {

            return true;
        }

        return rule.getHttpMethod()
                .equalsIgnoreCase(
                        endpoint.getHttpMethod()
                );
    }


    private boolean pathMatches(
            EndpointDefinition endpoint,
            RequestSecurityRule rule) {

        if (rule.getPattern() == null
                || rule.getPattern().isBlank()) {

            return false;
        }

        return pathMatcher.match(
                rule.getPattern(),
                endpoint.getPath()
        );
    }


    private AuthorizationDefinition copy(
            AuthorizationDefinition source) {

        return new AuthorizationDefinition(
                source.getAccessType(),
                source.getSecuritySource(),
                source.getRoles(),
                source.getRawExpression()
        );
    }
}