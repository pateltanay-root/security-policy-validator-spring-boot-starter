package com.research.securitypolicy.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import jakarta.servlet.ServletContext;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.RequestSecurityRule;

@SpringBootTest(
        classes =
                DefaultRequestSecurityAnalyzerIntegrationTest.TestConfiguration.class,
        properties = {
                "security-policy-validator.enabled=false"
        }
)
class DefaultRequestSecurityAnalyzerIntegrationTest {

    @Autowired
    private FilterChainProxy filterChainProxy;
    
    @Autowired
    private ServletContext servletContext;
    
    @Test
    void shouldAnalyzeMultipleRealSpringSecurityRules() {

        SecurityFilterChainAnalyzer chainAnalyzer =
                new SecurityFilterChainAnalyzer(
                        filterChainProxy
                );

        RequestAuthorizationEvaluator evaluator =
                new RequestAuthorizationEvaluator(
                        chainAnalyzer.getAuthorizationFilter()
                );

        AuthorizationRequestFactory requestFactory =
                new SimpleAuthorizationRequestFactory(
                        servletContext
                );

        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );


        /*
         * PUBLIC endpoint
         */
        EndpointDefinition publicEndpoint =
                new EndpointDefinition();

        publicEndpoint.setHttpMethod("GET");
        publicEndpoint.setPath(
                "/api/public/test"
        );


        /*
         * AUTHENTICATED endpoint
         */
        EndpointDefinition profileEndpoint =
                new EndpointDefinition();

        profileEndpoint.setHttpMethod("GET");
        profileEndpoint.setPath(
                "/api/profile"
        );


        /*
         * ROLE_BASED endpoint
         */
        EndpointDefinition adminEndpoint =
                new EndpointDefinition();

        adminEndpoint.setHttpMethod("GET");
        adminEndpoint.setPath(
                "/api/admin/users"
        );


        List<RequestSecurityRule> rules =
                analyzer.analyze(
                        List.of(
                                publicEndpoint,
                                profileEndpoint,
                                adminEndpoint
                        )
                );


        /*
         * We supplied three endpoints,
         * therefore three rules should be produced.
         */
        assertEquals(
                3,
                rules.size()
        );


        /*
         * ==========================================
         * PUBLIC
         * ==========================================
         */

        RequestSecurityRule publicRule =
                rules.get(0);

        assertEquals(
                "/api/public/test",
                publicRule.getPattern()
        );

        assertEquals(
                AccessType.PUBLIC,
                publicRule.getAccessType()
        );

        assertEquals(
                "permitAll",
                publicRule.getRawRule()
        );


        /*
         * ==========================================
         * AUTHENTICATED
         * ==========================================
         */

        RequestSecurityRule profileRule =
                rules.get(1);

        assertEquals(
                "/api/profile",
                profileRule.getPattern()
        );

        assertEquals(
                AccessType.AUTHENTICATED,
                profileRule.getAccessType()
        );

        assertEquals(
                "authenticated",
                profileRule.getRawRule()
        );


        /*
         * ==========================================
         * ROLE_BASED
         * ==========================================
         */

        RequestSecurityRule adminRule =
                rules.get(2);

        assertEquals(
                "/api/admin/users",
                adminRule.getPattern()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                adminRule.getAccessType()
        );

        assertEquals(
                List.of("ADMIN"),
                adminRule.getRoles()
        );

        assertEquals(
                "hasRole(ADMIN)",
                adminRule.getRawRule()
        );
    }

    @Test
    void shouldAnalyzePublicEndpoint() {

        SecurityFilterChainAnalyzer chainAnalyzer =
                new SecurityFilterChainAnalyzer(
                        filterChainProxy
                );

        RequestAuthorizationEvaluator evaluator =
                new RequestAuthorizationEvaluator(
                        chainAnalyzer.getAuthorizationFilter()
                );

        AuthorizationRequestFactory requestFactory =
                new SimpleAuthorizationRequestFactory(
                        servletContext
                );

        DefaultRequestSecurityAnalyzer analyzer =
                new DefaultRequestSecurityAnalyzer(
                        evaluator,
                        requestFactory
                );

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod("GET");
        endpoint.setPath("/api/public/test");

        List<RequestSecurityRule> rules =
                analyzer.analyze(
                        List.of(endpoint)
                );

        assertEquals(1, rules.size());

        assertEquals(
                AccessType.PUBLIC,
                rules.get(0).getAccessType()
        );
    }

    @Configuration
    @EnableAutoConfiguration
    static class TestConfiguration {

        @Bean
        SecurityFilterChain securityFilterChain(
                HttpSecurity http)
                throws Exception {

            http.authorizeHttpRequests(
                    authorization ->
                            authorization

                                    .requestMatchers(
                                            "/api/public/**"
                                    )
                                    .permitAll()

                                    .requestMatchers(
                                            "/api/admin/**"
                                    )
                                    .hasRole("ADMIN")

                                    .anyRequest()
                                    .authenticated()
            );

            return http.build();
        }
    }
}