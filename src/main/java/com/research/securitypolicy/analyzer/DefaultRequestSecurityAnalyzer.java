package com.research.securitypolicy.analyzer;

import java.util.List;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;

public class DefaultRequestSecurityAnalyzer
        implements RequestSecurityAnalyzer {

    private final RequestAuthorizationEvaluator evaluator;
    private final AuthorizationRequestFactory requestFactory;
    
    public DefaultRequestSecurityAnalyzer(
            RequestAuthorizationEvaluator evaluator,
            AuthorizationRequestFactory requestFactory) {

        if (evaluator == null) {
            throw new IllegalArgumentException(
                    "RequestAuthorizationEvaluator must not be null"
            );
        }

        if (requestFactory == null) {
            throw new IllegalArgumentException(
                    "AuthorizationRequestFactory must not be null"
            );
        }

        this.evaluator = evaluator;
        this.requestFactory = requestFactory;
    }


    @Override
    public List<RequestSecurityRule> analyze(
            List<EndpointDefinition> endpoints) {

        List<RequestSecurityRule> rules =
                new java.util.ArrayList<>();

        if (endpoints == null || endpoints.isEmpty()) {
            return rules;
        }

        for (EndpointDefinition endpoint : endpoints) {

            var request =
                    requestFactory.create(endpoint);

            boolean anonymousGranted =
                    evaluator.isGranted(
                            request,
                            anonymous()
                    );

            boolean userGranted =
                    evaluator.isGranted(
                            request,
                            user()
                    );

            boolean adminGranted =
                    evaluator.isGranted(
                            request,
                            admin()
                    );

            AccessType accessType =
                    inferAccessType(
                            anonymousGranted,
                            userGranted,
                            adminGranted
                    );

            List<String> roles =
                    new java.util.ArrayList<>();

            if (accessType == AccessType.ROLE_BASED
                    && adminGranted) {

                roles.add("ADMIN");
            }

            RequestSecurityRule rule =
                    new RequestSecurityRule(
                            endpoint.getPath(),
                            endpoint.getHttpMethod(),
                            accessType,
                            roles,
                            buildRawRule(
                                    accessType,
                                    roles
                            )
                    );

            rules.add(rule);
        }

        return rules;
    }
    
    private String buildRawRule(
            AccessType accessType,
            List<String> roles) {

        if (accessType == AccessType.PUBLIC) {
            return "permitAll";
        }

        if (accessType == AccessType.AUTHENTICATED) {
            return "authenticated";
        }

        if (accessType == AccessType.ROLE_BASED) {

            if (!roles.isEmpty()) {
                return "hasRole(" + roles.get(0) + ")";
            }

            return "roleBased";
        }

        return "unknown";
    }


    Authentication anonymous() {

        return new AnonymousAuthenticationToken(
                "security-policy-validator",
                "anonymousUser",
                List.of(
                        new SimpleGrantedAuthority(
                                "ROLE_ANONYMOUS"
                        )
                )
        );
    }


    Authentication user() {

        return UsernamePasswordAuthenticationToken
                .authenticated(
                        "user",
                        "password",
                        List.of(
                                new SimpleGrantedAuthority(
                                        "ROLE_USER"
                                )
                        )
                );
    }


    Authentication admin() {

        return UsernamePasswordAuthenticationToken
                .authenticated(
                        "admin",
                        "password",
                        List.of(
                                new SimpleGrantedAuthority(
                                        "ROLE_ADMIN"
                                )
                        )
                );
    }


    AccessType inferAccessType(
            boolean anonymousGranted,
            boolean userGranted,
            boolean adminGranted) {

        /*
         * Anonymous access means the endpoint
         * behaves as PUBLIC.
         */
        if (anonymousGranted) {
            return AccessType.PUBLIC;
        }


        /*
         * A normal authenticated user can access it,
         * therefore authentication is required but
         * no tested role restriction was detected.
         */
        if (userGranted) {
            return AccessType.AUTHENTICATED;
        }


        /*
         * Normal user denied, ADMIN allowed.
         *
         * Treat this as role-based authorization.
         */
        if (adminGranted) {
            return AccessType.ROLE_BASED;
        }


        /*
         * None of our current identities can access
         * the endpoint.
         *
         * For now AUTHENTICATED is used as the
         * conservative fallback.
         *
         * Later we can add a DENY_ALL access type
         * and improve this classification.
         */
        return AccessType.AUTHENTICATED;
    }


    RequestAuthorizationEvaluator getEvaluator() {
        return evaluator;
    }
}