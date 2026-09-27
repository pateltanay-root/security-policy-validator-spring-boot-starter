package com.research.securitypolicy.analyzer;

import java.util.ArrayList;
import java.util.List;

import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;

/**
 * Infers the runtime security requirements of discovered
 * Spring MVC endpoints.
 *
 * This class does not know HOW requests are executed.
 * That responsibility belongs to SecurityRequestExecutor.
 */
public class RuntimeRequestSecurityAnalyzer
        implements RequestSecurityAnalyzer {

    private final SecurityRequestExecutor executor;

    private final List<String> candidateRoles;


    public RuntimeRequestSecurityAnalyzer(
            SecurityRequestExecutor executor,
            List<String> candidateRoles) {

        if (executor == null) {
            throw new IllegalArgumentException(
                    "SecurityRequestExecutor must not be null"
            );
        }

        this.executor = executor;

        this.candidateRoles =
                candidateRoles == null
                        ? List.of()
                        : new ArrayList<>(candidateRoles);
    }


    @Override
    public List<RequestSecurityRule> analyze(
            List<EndpointDefinition> endpoints) {

        List<RequestSecurityRule> rules =
                new ArrayList<>();

        if (endpoints == null || endpoints.isEmpty()) {
            return rules;
        }


        for (EndpointDefinition endpoint : endpoints) {

            RequestSecurityRule rule =
                    analyzeEndpoint(endpoint);

            rules.add(rule);
        }


        return rules;
    }


    private RequestSecurityRule analyzeEndpoint(
            EndpointDefinition endpoint) {

        /*
         * --------------------------------------------
         * 1. Anonymous access
         * --------------------------------------------
         */
        if (executor.isAllowedAnonymous(endpoint)) {

            return new RequestSecurityRule(
                    endpoint.getPath(),
                    endpoint.getHttpMethod(),
                    AccessType.PUBLIC,
                    List.of(),
                    "permitAll"
            );
        }


        /*
         * --------------------------------------------
         * 2. Plain authenticated access
         *
         * No special role is supplied.
         * --------------------------------------------
         */
        if (executor.isAllowedAuthenticated(endpoint)) {

            return new RequestSecurityRule(
                    endpoint.getPath(),
                    endpoint.getHttpMethod(),
                    AccessType.AUTHENTICATED,
                    List.of(),
                    "authenticated"
            );
        }


        /*
         * --------------------------------------------
         * 3. Probe candidate roles.
         *
         * Example:
         *
         * ADMIN
         * USER
         * MANAGER
         * AUDITOR
         * --------------------------------------------
         */
        List<String> allowedRoles =
                new ArrayList<>();


        for (String role : candidateRoles) {

            if (role == null || role.isBlank()) {
                continue;
            }

            String normalizedRole =
                    normalizeRole(role);


            boolean allowed =
                    executor.isAllowedWithRoles(
                            endpoint,
                            List.of(normalizedRole)
                    );


            if (allowed) {
                allowedRoles.add(
                        normalizedRole
                );
            }
        }


        /*
         * At least one role succeeded.
         *
         * Therefore this endpoint appears to use
         * role-based authorization.
         */
        if (!allowedRoles.isEmpty()) {

            return new RequestSecurityRule(
                    endpoint.getPath(),
                    endpoint.getHttpMethod(),
                    AccessType.ROLE_BASED,
                    allowedRoles,
                    "roles=" + allowedRoles
            );
        }


        /*
         * No tested identity was able to access
         * the endpoint.
         *
         * Our current AccessType model does not yet
         * contain DENY_ALL / UNKNOWN.
         *
         * Therefore use AUTHENTICATED as a temporary
         * conservative fallback.
         *
         * We can improve this later by introducing
         * AccessType.DENY_ALL.
         */
        return new RequestSecurityRule(
                endpoint.getPath(),
                endpoint.getHttpMethod(),
                AccessType.AUTHENTICATED,
                List.of(),
                "unresolved"
        );
    }


    private String normalizeRole(
            String role) {

        String normalized =
                role
                        .trim()
                        .toUpperCase();


        if (normalized.startsWith("ROLE_")) {

            normalized =
                    normalized.substring(
                            "ROLE_".length()
                    );
        }


        return normalized;
    }
}