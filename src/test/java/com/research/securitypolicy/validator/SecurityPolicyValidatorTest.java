package com.research.securitypolicy.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.research.securitypolicy.model.RequestSecurityRule;
import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.AuthorizationDefinition;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.SecuritySource;
import com.research.securitypolicy.policy.ApiPolicy;

class SecurityPolicyValidatorTest {

    private final SecurityPolicyValidator validator =
            new SecurityPolicyValidator();
    
    @Test
    void shouldDetectRequestSecurityAccessMismatch() {

        SecurityPolicyValidator validator =
                new SecurityPolicyValidator();

        RequestSecurityRule actualRule =
                new RequestSecurityRule(
                        "/api/admin/users",
                        "GET",
                        AccessType.AUTHENTICATED,
                        List.of(),
                        "authenticated"
                );

        ApiPolicy policy =
                new ApiPolicy();

        policy.setMethod("GET");
        policy.setEndpoint("/api/admin/users");
        policy.setAccess("ROLE_BASED");
        policy.setRoles(
                List.of("ADMIN")
        );

        List<ValidationResult> results =
                validator.validateRequestSecurity(
                        List.of(actualRule),
                        List.of(policy)
                );

        assertEquals(
                1,
                results.size()
        );

        assertEquals(
                ViolationType.ACCESS_TYPE_MISMATCH,
                results.get(0).getViolationType()
        );

        assertEquals(
                Severity.CRITICAL,
                results.get(0).getSeverity()
        );
    }
    
    @Test
    void shouldAcceptMatchingRoleBasedRequestSecurity() {

        SecurityPolicyValidator validator =
                new SecurityPolicyValidator();

        RequestSecurityRule actualRule =
                new RequestSecurityRule(
                        "/api/admin/users",
                        "GET",
                        AccessType.ROLE_BASED,
                        List.of("ADMIN"),
                        "hasRole(ADMIN)"
                );

        ApiPolicy policy =
                new ApiPolicy();

        policy.setMethod("GET");
        policy.setEndpoint("/api/admin/users");
        policy.setAccess("ROLE_BASED");
        policy.setRoles(
                List.of("ADMIN")
        );

        List<ValidationResult> results =
                validator.validateRequestSecurity(
                        List.of(actualRule),
                        List.of(policy)
                );

        assertTrue(
                results.isEmpty()
        );
    }

    @Test
    void shouldAcceptMatchingRolePolicy() {

        EndpointDefinition endpoint =
                endpoint(
                        "PUT",
                        "/api/orders/{id}",
                        AccessType.ROLE_BASED,
                        List.of(
                                "ADMIN",
                                "MANAGER"
                        )
                );

        ApiPolicy policy =
                policy(
                        "PUT",
                        "/api/orders/{id}",
                        "ROLE_BASED",
                        List.of(
                                "ADMIN",
                                "MANAGER"
                        )
                );

        List<ValidationResult> results =
                validator.validate(
                        List.of(endpoint),
                        List.of(policy)
                );

        assertTrue(results.isEmpty());
    }


    @Test
    void shouldDetectMissingAuthentication() {

        EndpointDefinition endpoint =
                endpoint(
                        "GET",
                        "/api/profile",
                        AccessType.PUBLIC,
                        List.of()
                );

        ApiPolicy policy =
                policy(
                        "GET",
                        "/api/profile",
                        "AUTHENTICATED",
                        List.of()
                );

        ValidationResult result =
                singleResult(
                        endpoint,
                        policy
                );

        assertEquals(
                ViolationType.AUTHENTICATION_MISSING,
                result.getViolationType()
        );

        assertEquals(
                Severity.CRITICAL,
                result.getSeverity()
        );
    }


    @Test
    void shouldDetectMissingAuthorization() {

        EndpointDefinition endpoint =
                endpoint(
                        "DELETE",
                        "/api/users/{id}",
                        AccessType.AUTHENTICATED,
                        List.of()
                );

        ApiPolicy policy =
                policy(
                        "DELETE",
                        "/api/users/{id}",
                        "ROLE_BASED",
                        List.of("ADMIN")
                );

        ValidationResult result =
                singleResult(
                        endpoint,
                        policy
                );

        assertEquals(
                ViolationType.AUTHORIZATION_MISSING,
                result.getViolationType()
        );

        assertEquals(
                Severity.CRITICAL,
                result.getSeverity()
        );
    }


    @Test
    void shouldDetectMissingRequiredRole() {

        EndpointDefinition endpoint =
                endpoint(
                        "PUT",
                        "/api/orders/{id}",
                        AccessType.ROLE_BASED,
                        List.of("ADMIN")
                );

        ApiPolicy policy =
                policy(
                        "PUT",
                        "/api/orders/{id}",
                        "ROLE_BASED",
                        List.of(
                                "ADMIN",
                                "MANAGER"
                        )
                );

        ValidationResult result =
                singleResult(
                        endpoint,
                        policy
                );

        assertEquals(
                ViolationType.ROLE_MISMATCH,
                result.getViolationType()
        );

        assertEquals(
                Severity.MEDIUM,
                result.getSeverity()
        );
    }


    @Test
    void shouldDetectUnauthorizedExtraRole() {

        EndpointDefinition endpoint =
                endpoint(
                        "DELETE",
                        "/api/accounts/{id}",
                        AccessType.ROLE_BASED,
                        List.of(
                                "ADMIN",
                                "GUEST"
                        )
                );

        ApiPolicy policy =
                policy(
                        "DELETE",
                        "/api/accounts/{id}",
                        "ROLE_BASED",
                        List.of("ADMIN")
                );

        ValidationResult result =
                singleResult(
                        endpoint,
                        policy
                );

        assertEquals(
                ViolationType.ROLE_MISMATCH,
                result.getViolationType()
        );

        assertEquals(
                Severity.CRITICAL,
                result.getSeverity()
        );
    }


    @Test
    void shouldDetectMissingPolicy() {

        EndpointDefinition endpoint =
                endpoint(
                        "GET",
                        "/api/unknown",
                        AccessType.PUBLIC,
                        List.of()
                );

        List<ValidationResult> results =
                validator.validate(
                        List.of(endpoint),
                        List.of()
                );

        assertEquals(
                1,
                results.size()
        );

        assertEquals(
                ViolationType.MISSING_POLICY,
                results.get(0)
                        .getViolationType()
        );
    }


    private ValidationResult singleResult(
            EndpointDefinition endpoint,
            ApiPolicy policy) {

        List<ValidationResult> results =
                validator.validate(
                        List.of(endpoint),
                        List.of(policy)
                );

        assertEquals(
                1,
                results.size()
        );

        return results.get(0);
    }


    private EndpointDefinition endpoint(
            String method,
            String path,
            AccessType accessType,
            List<String> roles) {

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod(method);
        endpoint.setPath(path);

        AuthorizationDefinition authorization =
                new AuthorizationDefinition(
                        accessType,
                        SecuritySource.PRE_AUTHORIZE,
                        roles,
                        null
                );

        endpoint.setAuthorization(
                authorization
        );

        return endpoint;
    }


    private ApiPolicy policy(
            String method,
            String path,
            String access,
            List<String> roles) {

        ApiPolicy policy =
                new ApiPolicy();

        policy.setMethod(method);
        policy.setEndpoint(path);
        policy.setAccess(access);
        policy.setRoles(roles);

        return policy;
    }
}