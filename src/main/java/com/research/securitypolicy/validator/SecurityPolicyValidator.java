package com.research.securitypolicy.validator;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.research.securitypolicy.model.RequestSecurityRule;
import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.AuthorizationDefinition;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.policy.ApiPolicy;

public class SecurityPolicyValidator {

    public List<ValidationResult> validate(
            List<EndpointDefinition> endpoints,
            List<ApiPolicy> policies) {

        List<ValidationResult> results =
                new ArrayList<>();

        if (endpoints == null) {
            return results;
        }

        for (EndpointDefinition endpoint : endpoints) {

            ApiPolicy policy =
                    findPolicy(
                            endpoint,
                            policies
                    );

            if (policy == null) {

                results.add(
                        new ValidationResult(
                                endpoint.getEndpointKey(),
                                ViolationType.MISSING_POLICY,
                                Severity.HIGH,
                                "No security policy defined for endpoint",
                                "Policy definition required",
                                "No policy found"
                        )
                );

                continue;
            }

            validateEndpoint(
                    endpoint,
                    policy,
                    results
            );
        }

        return results;
    }
    
    public List<ValidationResult> validateRequestSecurity(
            List<RequestSecurityRule> actualRules,
            List<ApiPolicy> policies) {

        List<ValidationResult> results =
                new ArrayList<>();

        if (actualRules == null) {
            return results;
        }

        for (RequestSecurityRule actualRule : actualRules) {

            ApiPolicy policy =
                    findPolicy(
                            actualRule,
                            policies
                    );

            if (policy == null) {

                results.add(
                        new ValidationResult(
                                buildRequestRuleKey(
                                        actualRule
                                ),
                                ViolationType.MISSING_POLICY,
                                Severity.HIGH,
                                "No security policy defined for request rule",
                                "Policy definition required",
                                "No policy found"
                        )
                );

                continue;
            }

            validateRequestRule(
                    actualRule,
                    policy,
                    results
            );
        }

        return results;
    }
    
    private void validateRequestRule(
            RequestSecurityRule actualRule,
            ApiPolicy policy,
            List<ValidationResult> results) {

        AccessType expectedAccess =
                parseExpectedAccessType(
                        policy.getAccess()
                );

        if (expectedAccess == null) {

            results.add(
                    new ValidationResult(
                            buildRequestRuleKey(
                                    actualRule
                            ),
                            ViolationType.UNKNOWN_ACCESS_TYPE,
                            Severity.HIGH,
                            "Unknown access type in security policy",
                            "PUBLIC, AUTHENTICATED or ROLE_BASED",
                            String.valueOf(
                                    policy.getAccess()
                            )
                    )
            );

            return;
        }


        if (expectedAccess
                != actualRule.getAccessType()) {

            Severity severity =
                    determineRequestAccessMismatchSeverity(
                            expectedAccess,
                            actualRule.getAccessType()
                    );

            results.add(
                    new ValidationResult(
                            buildRequestRuleKey(
                                    actualRule
                            ),
                            ViolationType.ACCESS_TYPE_MISMATCH,
                            severity,
                            "Actual Spring Security request authorization does not match policy",
                            expectedAccess.name(),
                            actualRule
                                    .getAccessType()
                                    .name()
                    )
            );

            return;
        }


        if (expectedAccess
                == AccessType.ROLE_BASED) {

            compareRequestRoles(
                    actualRule,
                    safeRoles(
                            policy.getRoles()
                    ),
                    results
            );
        }
    }
    
    private Severity determineRequestAccessMismatchSeverity(
            AccessType expected,
            AccessType actual) {

        /*
         * Policy expects protection,
         * but actual request is PUBLIC.
         */
        if (expected != AccessType.PUBLIC
                && actual == AccessType.PUBLIC) {

            return Severity.CRITICAL;
        }

        /*
         * Policy requires roles,
         * but actual security only checks authentication.
         */
        if (expected == AccessType.ROLE_BASED
                && actual == AccessType.AUTHENTICATED) {

            return Severity.CRITICAL;
        }

        /*
         * Actual configuration is stricter than policy.
         */
        return Severity.MEDIUM;
    }
    
    private void compareRequestRoles(
            RequestSecurityRule actualRule,
            List<String> expectedRoles,
            List<ValidationResult> results) {

        Set<String> expected =
                new HashSet<>(
                        normalizeRoles(
                                expectedRoles
                        )
                );

        Set<String> actual =
                new HashSet<>(
                        normalizeRoles(
                                actualRule.getRoles()
                        )
                );


        if (expected.equals(actual)) {
            return;
        }


        Set<String> unauthorizedRoles =
                new HashSet<>(actual);

        unauthorizedRoles.removeAll(expected);


        Set<String> missingRoles =
                new HashSet<>(expected);

        missingRoles.removeAll(actual);


        results.add(
                new ValidationResult(
                        buildRequestRuleKey(
                                actualRule
                        ),
                        ViolationType.ROLE_MISMATCH,
                        determineRoleMismatchSeverity(
                                unauthorizedRoles,
                                missingRoles
                        ),
                        "Actual Spring Security roles do not match policy roles",
                        expected.toString(),
                        actual.toString()
                )
        );
    }

    private void validateEndpoint(
            EndpointDefinition endpoint,
            ApiPolicy policy,
            List<ValidationResult> results) {

        AccessType expectedAccess =
                parseExpectedAccessType(
                        policy.getAccess()
                );

        if (expectedAccess == null) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.UNKNOWN_ACCESS_TYPE,
                            Severity.HIGH,
                            "Unknown access type in security policy",
                            "PUBLIC, AUTHENTICATED or ROLE_BASED",
                            String.valueOf(
                                    policy.getAccess()
                            )
                    )
            );

            return;
        }

        AuthorizationDefinition actual =
                endpoint.getAuthorization();

        /*
         * Defensive fallback for older
         * EndpointDefinition instances.
         */
        if (actual == null) {

            actual =
                    createLegacyAuthorization(
                            endpoint
                    );
        }

        switch (expectedAccess) {

            case PUBLIC ->
                    validatePublic(
                            endpoint,
                            policy,
                            actual,
                            results
                    );

            case AUTHENTICATED ->
                    validateAuthenticated(
                            endpoint,
                            policy,
                            actual,
                            results
                    );

            case ROLE_BASED ->
                    validateRoleBased(
                            endpoint,
                            policy,
                            actual,
                            results
                    );
        }
    }


    private void validatePublic(
            EndpointDefinition endpoint,
            ApiPolicy policy,
            AuthorizationDefinition actual,
            List<ValidationResult> results) {

        List<String> expectedRoles =
                safeRoles(
                        policy.getRoles()
                );

        /*
         * PUBLIC policies themselves should
         * never contain roles.
         */
        if (!expectedRoles.isEmpty()) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.INVALID_PUBLIC_POLICY,
                            Severity.HIGH,
                            "PUBLIC policy must not define roles",
                            "[]",
                            expectedRoles.toString()
                    )
            );

            return;
        }

        if (actual.getAccessType()
                != AccessType.PUBLIC) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.ACCESS_TYPE_MISMATCH,
                            Severity.MEDIUM,
                            "Endpoint is more restricted than the declared PUBLIC policy",
                            AccessType.PUBLIC.name(),
                            actual.getAccessType().name()
                    )
            );
        }
    }


    private void validateAuthenticated(
            EndpointDefinition endpoint,
            ApiPolicy policy,
            AuthorizationDefinition actual,
            List<ValidationResult> results) {

        List<String> expectedRoles =
                safeRoles(
                        policy.getRoles()
                );

        if (!expectedRoles.isEmpty()) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.INVALID_AUTHENTICATED_POLICY,
                            Severity.HIGH,
                            "AUTHENTICATED policy must not define roles",
                            "[]",
                            expectedRoles.toString()
                    )
            );

            return;
        }

        /*
         * Expected authentication, but actual
         * endpoint appears public.
         */
        if (actual.getAccessType()
                == AccessType.PUBLIC) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.AUTHENTICATION_MISSING,
                            Severity.CRITICAL,
                            "Endpoint requires authentication but no method-level protection was detected",
                            AccessType.AUTHENTICATED.name(),
                            AccessType.PUBLIC.name()
                    )
            );

            return;
        }

        /*
         * ROLE_BASED is more restrictive than
         * plain AUTHENTICATED, but it does not
         * conform exactly to the declared policy.
         */
        if (actual.getAccessType()
                != AccessType.AUTHENTICATED) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.ACCESS_TYPE_MISMATCH,
                            Severity.HIGH,
                            "Implemented access type does not match the security policy",
                            AccessType.AUTHENTICATED.name(),
                            actual.getAccessType().name()
                    )
            );
        }
    }


    private void validateRoleBased(
            EndpointDefinition endpoint,
            ApiPolicy policy,
            AuthorizationDefinition actual,
            List<ValidationResult> results) {

        List<String> expectedRoles =
                safeRoles(
                        policy.getRoles()
                );

        /*
         * A ROLE_BASED policy without roles
         * is not useful.
         */
        if (expectedRoles.isEmpty()) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.ACCESS_TYPE_MISMATCH,
                            Severity.HIGH,
                            "ROLE_BASED policy must define at least one role",
                            "One or more roles",
                            "[]"
                    )
            );

            return;
        }

        /*
         * Most dangerous case:
         * security team expects role protection,
         * but method security appears public.
         */
        if (actual.getAccessType()
                == AccessType.PUBLIC) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.AUTHORIZATION_MISSING,
                            Severity.CRITICAL,
                            "Role-based authorization is required but no method-level authorization was detected",
                            expectedRoles.toString(),
                            "PUBLIC"
                    )
            );

            return;
        }

        /*
         * Authentication exists, but role-level
         * authorization is missing.
         */
        if (actual.getAccessType()
                == AccessType.AUTHENTICATED) {

            results.add(
                    new ValidationResult(
                            endpoint.getEndpointKey(),
                            ViolationType.AUTHORIZATION_MISSING,
                            Severity.CRITICAL,
                            "Endpoint is authenticated but required role authorization is missing",
                            expectedRoles.toString(),
                            "AUTHENTICATED"
                    )
            );

            return;
        }

        compareRoles(
                endpoint,
                expectedRoles,
                actual.getRoles(),
                results
        );
    }


    private void compareRoles(
            EndpointDefinition endpoint,
            List<String> expectedRoles,
            List<String> actualRoles,
            List<ValidationResult> results) {

        Set<String> expected =
                new HashSet<>(
                        normalizeRoles(expectedRoles)
                );

        Set<String> actual =
                new HashSet<>(
                        normalizeRoles(actualRoles)
                );

        if (expected.equals(actual)) {
            return;
        }

        Set<String> unauthorizedRoles =
                new HashSet<>(actual);

        unauthorizedRoles.removeAll(expected);


        Set<String> missingRoles =
                new HashSet<>(expected);

        missingRoles.removeAll(actual);


        Severity severity =
                determineRoleMismatchSeverity(
                        unauthorizedRoles,
                        missingRoles
                );

        String message;

        if (!unauthorizedRoles.isEmpty()
                && !missingRoles.isEmpty()) {

            message =
                    "Endpoint contains unauthorized roles and is also missing required roles";

        } else if (!unauthorizedRoles.isEmpty()) {

            message =
                    "Endpoint grants access to roles not allowed by policy";

        } else {

            message =
                    "Endpoint is missing roles required by policy";
        }

        results.add(
                new ValidationResult(
                        endpoint.getEndpointKey(),
                        ViolationType.ROLE_MISMATCH,
                        severity,
                        message,
                        expected.toString(),
                        actual.toString()
                )
        );
    }


    private Severity determineRoleMismatchSeverity(
            Set<String> unauthorizedRoles,
            Set<String> missingRoles) {

        /*
         * Unauthorized access is the most
         * serious role mismatch.
         */
        if (!unauthorizedRoles.isEmpty()) {

            return Severity.CRITICAL;
        }

        /*
         * Required users cannot access,
         * but nobody gained extra access.
         */
        if (!missingRoles.isEmpty()) {

            return Severity.MEDIUM;
        }

        return Severity.LOW;
    }


    private ApiPolicy findPolicy(
            EndpointDefinition endpoint,
            List<ApiPolicy> policies) {

        if (policies == null) {
            return null;
        }

        String endpointKey =
                endpoint.getEndpointKey();

        return policies.stream()
                .filter(policy ->
                        endpointKey.equals(
                                policy.getPolicyKey()
                        )
                )
                .findFirst()
                .orElse(null);
    }
    
    private ApiPolicy findPolicy(
            RequestSecurityRule rule,
            List<ApiPolicy> policies) {

        if (policies == null) {
            return null;
        }

        String ruleKey =
                buildRequestRuleKey(rule);

        return policies.stream()
                .filter(policy ->
                        ruleKey.equals(
                                policy.getPolicyKey()
                        )
                )
                .findFirst()
                .orElse(null);
    }
    
    private String buildRequestRuleKey(
            RequestSecurityRule rule) {

        String method =
                rule.getHttpMethod() == null
                        ? ""
                        : rule.getHttpMethod()
                                .trim()
                                .toUpperCase();

        String pattern =
                rule.getPattern() == null
                        ? ""
                        : rule.getPattern().trim();

        return method + ":" + pattern;
    }


    private AccessType parseExpectedAccessType(
            String access) {

        if (access == null
                || access.isBlank()) {

            return AccessType.ROLE_BASED;
        }

        try {

            return AccessType.valueOf(
                    access
                            .trim()
                            .toUpperCase()
            );

        } catch (IllegalArgumentException exception) {

            return null;
        }
    }


    private AuthorizationDefinition
            createLegacyAuthorization(
                    EndpointDefinition endpoint) {

        String expression =
                endpoint
                        .getAuthorizationExpression();

        List<String> roles =
                safeRoles(
                        endpoint.getRoles()
                );

        AccessType accessType;

        if (expression == null
                || expression.isBlank()) {

            accessType =
                    AccessType.PUBLIC;

        } else if (!roles.isEmpty()) {

            accessType =
                    AccessType.ROLE_BASED;

        } else {

            accessType =
                    AccessType.AUTHENTICATED;
        }

        return new AuthorizationDefinition(
                accessType,
                null,
                roles,
                expression
        );
    }


    private List<String> safeRoles(
            List<String> roles) {

        return roles == null
                ? List.of()
                : roles;
    }


    private List<String> normalizeRoles(
            List<String> roles) {

        List<String> normalized =
                new ArrayList<>();

        if (roles == null) {
            return normalized;
        }

        for (String role : roles) {

            if (role == null) {
                continue;
            }

            String value =
                    role
                            .trim()
                            .toUpperCase();

            if (value.startsWith("ROLE_")) {

                value =
                        value.substring(
                                "ROLE_".length()
                        );
            }

            if (!value.isBlank()) {

                normalized.add(value);
            }
        }

        return normalized;
    }
}