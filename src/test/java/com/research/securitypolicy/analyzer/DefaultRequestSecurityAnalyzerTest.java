package com.research.securitypolicy.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import org.springframework.security.core.Authentication;

import com.research.securitypolicy.model.EndpointDefinition;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.RequestSecurityRule;

class DefaultRequestSecurityAnalyzerTest {

    @Test
    void shouldReturnEmptyRulesForEmptyEndpoints() {

        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );

        List<RequestSecurityRule> rules =
                analyzer.analyze(
                        List.of()
                );

        assertNotNull(rules);
        assertTrue(rules.isEmpty());
    }
    
    @Test
    void shouldCreateAuthenticatedRequestSecurityRule() {

        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        HttpServletRequest request =
                mock(HttpServletRequest.class);

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod("GET");
        endpoint.setPath("/api/profile");

        when(
                requestFactory.create(endpoint)
        ).thenReturn(request);


        /*
         * anonymous = denied
         * USER      = allowed
         * ADMIN     = allowed
         *
         * Expected:
         * AUTHENTICATED
         */
        when(
                evaluator.isGranted(
                        eq(request),
                        any(Authentication.class)
                )
        ).thenReturn(
                false,
                true,
                true
        );


        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );


        List<RequestSecurityRule> rules =
                analyzer.analyze(
                        List.of(endpoint)
                );


        assertEquals(
                1,
                rules.size()
        );

        RequestSecurityRule rule =
                rules.get(0);


        assertEquals(
                "/api/profile",
                rule.getPattern()
        );

        assertEquals(
                "GET",
                rule.getHttpMethod()
        );

        assertEquals(
                AccessType.AUTHENTICATED,
                rule.getAccessType()
        );

        assertTrue(
                rule.getRoles().isEmpty()
        );

        assertEquals(
                "authenticated",
                rule.getRawRule()
        );
    }
    
    @Test
    void shouldCreateRoleBasedRequestSecurityRule() {

        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        HttpServletRequest request =
                mock(HttpServletRequest.class);

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod("GET");
        endpoint.setPath("/api/admin/users");

        when(
                requestFactory.create(endpoint)
        ).thenReturn(request);


        /*
         * anonymous = denied
         * USER      = denied
         * ADMIN     = allowed
         *
         * Expected:
         * ROLE_BASED
         * role = ADMIN
         */
        when(
                evaluator.isGranted(
                        eq(request),
                        any(Authentication.class)
                )
        ).thenReturn(
                false,
                false,
                true
        );


        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );


        List<RequestSecurityRule> rules =
                analyzer.analyze(
                        List.of(endpoint)
                );


        assertEquals(
                1,
                rules.size()
        );

        RequestSecurityRule rule =
                rules.get(0);


        assertEquals(
                "/api/admin/users",
                rule.getPattern()
        );

        assertEquals(
                "GET",
                rule.getHttpMethod()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                rule.getAccessType()
        );

        assertEquals(
                List.of("ADMIN"),
                rule.getRoles()
        );

        assertEquals(
                "hasRole(ADMIN)",
                rule.getRawRule()
        );
    }
    
    @Test
    void shouldCreatePublicRequestSecurityRule() {

        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        HttpServletRequest request =
                mock(HttpServletRequest.class);

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod("GET");
        endpoint.setPath("/api/public/test");

        when(
                requestFactory.create(endpoint)
        ).thenReturn(request);

        /*
         * Anonymous, USER and ADMIN are all allowed.
         * Therefore this endpoint should be PUBLIC.
         */
        when(
                evaluator.isGranted(
                        eq(request),
                        any(Authentication.class)
                )
        ).thenReturn(true);

        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );

        List<RequestSecurityRule> rules =
                analyzer.analyze(
                        List.of(endpoint)
                );

        assertEquals(
                1,
                rules.size()
        );

        RequestSecurityRule rule =
                rules.get(0);

        assertEquals(
                "/api/public/test",
                rule.getPattern()
        );

        assertEquals(
                "GET",
                rule.getHttpMethod()
        );

        assertEquals(
                AccessType.PUBLIC,
                rule.getAccessType()
        );

        assertTrue(
                rule.getRoles().isEmpty()
        );

        assertEquals(
                "permitAll",
                rule.getRawRule()
        );
    }
    
    @Test
    void shouldEvaluateEndpointUsingRequestFactoryAndEvaluator() {

        /*
         * 1. Mock dependencies
         */
        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        HttpServletRequest request =
                mock(HttpServletRequest.class);


        /*
         * 2. Create endpoint
         */
        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod("GET");
        endpoint.setPath("/api/users");


        /*
         * 3. Factory should return our request
         */
        when(
                requestFactory.create(endpoint)
        ).thenReturn(request);


        /*
         * 4. Simulate PUBLIC access for now.
         *
         * Every identity is allowed.
         */
        when(
                evaluator.isGranted(
                        eq(request),
                        any(Authentication.class)
                )
        ).thenReturn(true);


        /*
         * 5. Create analyzer
         */
        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );


        /*
         * 6. Analyze one endpoint
         */
        analyzer.analyze(
                List.of(endpoint)
        );


        /*
         * 7. Endpoint must be converted to a request once
         */
        verify(
                requestFactory,
                times(1)
        ).create(endpoint);


        /*
         * 8. Authorization must be evaluated three times:
         *
         * anonymous
         * USER
         * ADMIN
         */
        verify(
                evaluator,
                times(3)
        ).isGranted(
                eq(request),
                any(Authentication.class)
        );
    }

    @Test
    void shouldInferPublicAccess() {

        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );

        assertEquals(
                AccessType.PUBLIC,
                analyzer.inferAccessType(
                        true,
                        true,
                        true
                )
        );
    }


    @Test
    void shouldInferAuthenticatedAccess() {

        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );

        assertEquals(
                AccessType.AUTHENTICATED,
                analyzer.inferAccessType(
                        false,
                        true,
                        true
                )
        );
    }


    @Test
    void shouldInferRoleBasedAccess() {

        RequestAuthorizationEvaluator evaluator =
                mock(RequestAuthorizationEvaluator.class);

        AuthorizationRequestFactory requestFactory =
                mock(AuthorizationRequestFactory.class);

        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );

        assertEquals(
                AccessType.ROLE_BASED,
                analyzer.inferAccessType(
                        false,
                        false,
                        true
                )
        );
    }
}