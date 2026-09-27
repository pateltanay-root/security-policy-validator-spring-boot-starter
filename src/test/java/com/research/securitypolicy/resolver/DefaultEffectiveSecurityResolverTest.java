package com.research.securitypolicy.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.AuthorizationDefinition;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;
import com.research.securitypolicy.model.SecuritySource;

class DefaultEffectiveSecurityResolverTest {

    private final EffectiveSecurityResolver resolver =
            new DefaultEffectiveSecurityResolver();


    @Test
    void shouldPreserveMethodLevelSecurity() {

        EndpointDefinition endpoint =
                endpoint(
                        "DELETE",
                        "/api/users/{id}"
                );

        endpoint.setAuthorization(
                new AuthorizationDefinition(
                        AccessType.ROLE_BASED,
                        SecuritySource.PRE_AUTHORIZE,
                        List.of("ADMIN"),
                        "hasRole('ADMIN')"
                )
        );

        AuthorizationDefinition result =
                resolver.resolve(
                        endpoint,
                        List.of()
                );

        assertNotNull(result);

        assertEquals(
                AccessType.ROLE_BASED,
                result.getAccessType()
        );

        assertEquals(
                SecuritySource.PRE_AUTHORIZE,
                result.getSecuritySource()
        );

        assertEquals(
                List.of("ADMIN"),
                result.getRoles()
        );
    }


    @Test
    void shouldUseAuthenticatedRequestRule() {

        EndpointDefinition endpoint =
                unprotectedEndpoint(
                        "GET",
                        "/api/profile"
                );

        RequestSecurityRule rule =
                new RequestSecurityRule(
                        "/api/**",
                        null,
                        AccessType.AUTHENTICATED,
                        List.of(),
                        "authenticated()"
                );

        AuthorizationDefinition result =
                resolver.resolve(
                        endpoint,
                        List.of(rule)
                );

        assertNotNull(result);

        assertEquals(
                AccessType.AUTHENTICATED,
                result.getAccessType()
        );

        assertEquals(
                SecuritySource.SECURITY_FILTER_CHAIN,
                result.getSecuritySource()
        );
    }


    @Test
    void shouldUseRoleBasedRequestRule() {

        EndpointDefinition endpoint =
                unprotectedEndpoint(
                        "GET",
                        "/api/admin/users"
                );

        RequestSecurityRule rule =
                new RequestSecurityRule(
                        "/api/admin/**",
                        null,
                        AccessType.ROLE_BASED,
                        List.of("ADMIN"),
                        "hasRole('ADMIN')"
                );

        AuthorizationDefinition result =
                resolver.resolve(
                        endpoint,
                        List.of(rule)
                );

        assertEquals(
                AccessType.ROLE_BASED,
                result.getAccessType()
        );

        assertEquals(
                List.of("ADMIN"),
                result.getRoles()
        );

        assertEquals(
                SecuritySource.SECURITY_FILTER_CHAIN,
                result.getSecuritySource()
        );
    }


    @Test
    void shouldRespectHttpMethod() {

        EndpointDefinition endpoint =
                unprotectedEndpoint(
                        "GET",
                        "/api/users"
                );

        RequestSecurityRule postRule =
                new RequestSecurityRule(
                        "/api/users",
                        "POST",
                        AccessType.ROLE_BASED,
                        List.of("ADMIN"),
                        "POST ADMIN"
                );

        RequestSecurityRule getRule =
                new RequestSecurityRule(
                        "/api/users",
                        "GET",
                        AccessType.AUTHENTICATED,
                        List.of(),
                        "GET authenticated"
                );

        AuthorizationDefinition result =
                resolver.resolve(
                        endpoint,
                        List.of(
                                postRule,
                                getRule
                        )
                );

        assertEquals(
                AccessType.AUTHENTICATED,
                result.getAccessType()
        );
    }


    @Test
    void shouldUseFirstMatchingRule() {

        EndpointDefinition endpoint =
                unprotectedEndpoint(
                        "GET",
                        "/api/admin/reports"
                );

        RequestSecurityRule adminRule =
                new RequestSecurityRule(
                        "/api/admin/**",
                        null,
                        AccessType.ROLE_BASED,
                        List.of("ADMIN"),
                        "ADMIN RULE"
                );

        RequestSecurityRule fallbackRule =
                new RequestSecurityRule(
                        "/api/**",
                        null,
                        AccessType.AUTHENTICATED,
                        List.of(),
                        "AUTHENTICATED RULE"
                );

        AuthorizationDefinition result =
                resolver.resolve(
                        endpoint,
                        List.of(
                                adminRule,
                                fallbackRule
                        )
                );

        assertEquals(
                AccessType.ROLE_BASED,
                result.getAccessType()
        );

        assertEquals(
                List.of("ADMIN"),
                result.getRoles()
        );
    }


    private EndpointDefinition unprotectedEndpoint(
            String method,
            String path) {

        EndpointDefinition endpoint =
                endpoint(method, path);

        endpoint.setAuthorization(
                new AuthorizationDefinition(
                        AccessType.PUBLIC,
                        SecuritySource.NONE,
                        List.of(),
                        null
                )
        );

        return endpoint;
    }


    private EndpointDefinition endpoint(
            String method,
            String path) {

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod(method);
        endpoint.setPath(path);

        return endpoint;
    }
}