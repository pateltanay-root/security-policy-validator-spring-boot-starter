package com.research.securitypolicy.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request
        .SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup
        .SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request
        .MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request
        .MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result
        .MockMvcResultMatchers.status;

import java.io.InputStream;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.research.securitypolicy.validator.Severity;
import com.research.securitypolicy.validator.ViolationType;
import com.research.securitypolicy.analyzer.MockMvcSecurityRequestExecutor;
import com.research.securitypolicy.analyzer.RuntimeRequestSecurityAnalyzer;
import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.RequestSecurityRule;
import com.research.securitypolicy.loader.PolicyLoader;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.policy.ApiPolicy;
import com.research.securitypolicy.scanner.EndpointScanner;
import com.research.securitypolicy.scanner.TestController;
import com.research.securitypolicy.validator.SecurityPolicyValidator;
import com.research.securitypolicy.validator.ValidationResult;


@SpringBootTest(
        classes =
                SecurityPolicyIntegrationTest
                        .TestConfiguration.class,
        properties = {
                "security-policy-validator.enabled=false"
        }
)
class SecurityPolicyIntegrationTest {


    @Autowired
    private RequestMappingHandlerMapping handlerMapping;


    @Autowired
    private WebApplicationContext webApplicationContext;


    private MockMvc mockMvc;


    /*
     * Build MockMvc manually using the real
     * Spring WebApplicationContext and apply
     * the Spring Security filter chain.
     */
    @BeforeEach
    void setUpMockMvc() {

        mockMvc =
                MockMvcBuilders
                        .webAppContextSetup(
                                webApplicationContext
                        )
                        .apply(
                                springSecurity()
                        )
                        .build();
    }


    /*
     * ====================================================
     * TEST 1
     *
     * EndpointScanner
     *      +
     * YAML Policy
     *      ↓
     * Method-level policy validation
     *
     * This verifies annotations such as:
     *
     * @PreAuthorize
     * @Secured
     * @RolesAllowed
     * ====================================================
     */
    @Test
    void shouldValidateCompleteSecurityPolicyPipeline() {

        EndpointScanner scanner =
                new EndpointScanner(
                        handlerMapping
                );


        List<EndpointDefinition> endpoints =
                scanner.scanEndpoints();


        List<ApiPolicy> policies =
                loadPolicies();


        SecurityPolicyValidator validator =
                new SecurityPolicyValidator();


        List<ValidationResult> results =
                validator.validate(
                        endpoints,
                        policies
                );


        System.out.println(
                "\n=== METHOD-LEVEL SECURITY VALIDATION ==="
        );


        for (ValidationResult result : results) {

            System.out.println(
                    result.getEndpoint()
                            + " -> "
                            + result.getViolationType()
                            + " -> "
                            + result.getSeverity()
            );
        }


        assertTrue(
                results.isEmpty(),
                "Expected no method-level security-policy violations"
        );
    }


    /*
     * ====================================================
     * TEST 2
     *
     * Verify request-level Spring Security by sending
     * requests through the REAL security filter chain.
     *
     * Configuration:
     *
     * /api/test/public
     *      -> permitAll()
     *
     * /api/test/**
     *      -> hasRole("ADMIN")
     * ====================================================
     */
    @Test
    void shouldValidateSecurityThroughRealFilterChain()
            throws Exception {


        /*
         * PUBLIC endpoint.
         *
         * No authentication should be required.
         */
        mockMvc.perform(
                get(
                        "/api/test/public"
                )
        )
        .andExpect(
                status().isOk()
        );


        /*
         * ADMIN-protected endpoint.
         *
         * USER must be rejected.
         */
        mockMvc.perform(
                delete(
                        "/api/test/1"
                )
                .with(
                        user(
                                "normal-user"
                        )
                        .roles(
                                "USER"
                        )
                )
        )
        .andExpect(
                status().isForbidden()
        );


        /*
         * ADMIN-protected endpoint.
         *
         * ADMIN must be allowed.
         */
        mockMvc.perform(
                delete(
                        "/api/test/1"
                )
                .with(
                        user(
                                "admin-user"
                        )
                        .roles(
                                "ADMIN"
                        )
                )
        )
        .andExpect(
                status().isOk()
        );


        System.out.println(
                "\n=== REAL FILTER CHAIN VALIDATION ==="
        );

        System.out.println(
                "GET /api/test/public -> PUBLIC"
        );

        System.out.println(
                "DELETE /api/test/1 with USER -> DENIED"
        );

        System.out.println(
                "DELETE /api/test/1 with ADMIN -> ALLOWED"
        );
    }
    
    @Test
    void shouldDetectRuntimeRoleMismatch() {

        EndpointScanner scanner =
                new EndpointScanner(
                        handlerMapping
                );

        List<EndpointDefinition> endpoints =
                scanner.scanEndpoints();


        List<EndpointDefinition> endpointsToAnalyze =
                endpoints.stream()
                        .filter(endpoint ->
                                endpoint.getEndpointKey()
                                        .equals(
                                                "DELETE:/api/test/{id}"
                                        )
                        )
                        .toList();


        MockMvcSecurityRequestExecutor executor =
                new MockMvcSecurityRequestExecutor(
                        mockMvc
                );


        RuntimeRequestSecurityAnalyzer analyzer =
                new RuntimeRequestSecurityAnalyzer(
                        executor,
                        List.of(
                                "USER",
                                "ADMIN",
                                "MANAGER",
                                "AUDITOR"
                        )
                );


        List<RequestSecurityRule> actualRules =
                analyzer.analyze(
                        endpointsToAnalyze
                );


        /*
         * The actual Spring Security configuration
         * requires ADMIN.
         *
         * Now deliberately create a WRONG policy
         * expecting USER.
         */
        ApiPolicy wrongPolicy =
                new ApiPolicy();

        wrongPolicy.setMethod(
                "DELETE"
        );

        wrongPolicy.setEndpoint(
                "/api/test/{id}"
        );

        wrongPolicy.setAccess(
                "ROLE_BASED"
        );

        wrongPolicy.setRoles(
                List.of(
                        "USER"
                )
        );


        SecurityPolicyValidator validator =
                new SecurityPolicyValidator();


        List<ValidationResult> results =
                validator.validateRequestSecurity(
                        actualRules,
                        List.of(
                                wrongPolicy
                        )
                );


        System.out.println(
                "\n=== NEGATIVE RUNTIME VALIDATION ==="
        );


        for (RequestSecurityRule rule : actualRules) {

            System.out.println(
                    rule.getHttpMethod()
                            + ":"
                            + rule.getPattern()
                            + " -> "
                            + rule.getAccessType()
                            + " -> "
                            + rule.getRoles()
            );
        }


        for (ValidationResult result : results) {

            System.out.println(
                    result.getEndpoint()
                            + " -> "
                            + result.getViolationType()
                            + " -> "
                            + result.getSeverity()
            );
        }


        assertEquals(
                1,
                results.size()
        );


        ValidationResult violation =
                results.get(0);


        assertEquals(
                ViolationType.ROLE_MISMATCH,
                violation.getViolationType()
        );


        assertEquals(
                Severity.CRITICAL,
                violation.getSeverity()
        );
    }
    
    @Test
    void shouldInferRuntimeSecurityRules()
            throws Exception {

        EndpointScanner scanner =
                new EndpointScanner(
                        handlerMapping
                );

        List<EndpointDefinition> endpoints =
                scanner.scanEndpoints();

        List<EndpointDefinition> endpointsToAnalyze =
                endpoints.stream()
                        .filter(endpoint -> {
                            String key =
                                    endpoint.getEndpointKey();

                            return key.equals(
                                    "GET:/api/test/public"
                            )
                            ||
                            key.equals(
                                    "DELETE:/api/test/{id}"
                            );
                        })
                        .toList();


        MockMvcSecurityRequestExecutor executor =
                new MockMvcSecurityRequestExecutor(
                        mockMvc
                );


        RuntimeRequestSecurityAnalyzer analyzer =
                new RuntimeRequestSecurityAnalyzer(
                        executor,
                        List.of(
                                "USER",
                                "ADMIN",
                                "MANAGER",
                                "AUDITOR"
                        )
                );


        List<RequestSecurityRule> rules =
                analyzer.analyze(
                        endpointsToAnalyze
                );


        System.out.println(
                "\n=== RUNTIME SECURITY ANALYSIS ==="
        );

        for (RequestSecurityRule rule : rules) {

            System.out.println(
                    rule.getHttpMethod()
                            + ":"
                            + rule.getPattern()
                            + " -> "
                            + rule.getAccessType()
                            + " -> "
                            + rule.getRoles()
            );
        }


        RequestSecurityRule publicRule =
                rules.stream()
                        .filter(rule ->
                                "GET".equals(
                                        rule.getHttpMethod()
                                )
                        )
                        .findFirst()
                        .orElseThrow();


        RequestSecurityRule deleteRule =
                rules.stream()
                        .filter(rule ->
                                "DELETE".equals(
                                        rule.getHttpMethod()
                                )
                        )
                        .findFirst()
                        .orElseThrow();


        assertEquals(
                AccessType.PUBLIC,
                publicRule.getAccessType()
        );


        assertEquals(
                AccessType.ROLE_BASED,
                deleteRule.getAccessType()
        );


        assertTrue(
                deleteRule
                        .getRoles()
                        .contains("ADMIN")
        );
    }
    
    @Test
    void shouldValidateRuntimeSecurityAgainstPolicy() {

        EndpointScanner scanner =
                new EndpointScanner(handlerMapping);

        List<EndpointDefinition> endpoints =
                scanner.scanEndpoints();

        List<EndpointDefinition> endpointsToAnalyze =
                endpoints.stream()
                        .filter(endpoint -> {
                            String key = endpoint.getEndpointKey();

                            return key.equals(
                                    "GET:/api/test/public"
                            )
                            ||
                            key.equals(
                                    "DELETE:/api/test/{id}"
                            );
                        })
                        .toList();


        MockMvcSecurityRequestExecutor executor =
                new MockMvcSecurityRequestExecutor(
                        mockMvc
                );


        RuntimeRequestSecurityAnalyzer analyzer =
                new RuntimeRequestSecurityAnalyzer(
                        executor,
                        List.of(
                                "USER",
                                "ADMIN",
                                "MANAGER",
                                "AUDITOR"
                        )
                );


        List<RequestSecurityRule> actualRules =
                analyzer.analyze(
                        endpointsToAnalyze
                );


        List<ApiPolicy> policies =
                loadPolicies();


        SecurityPolicyValidator validator =
                new SecurityPolicyValidator();


        List<ValidationResult> results =
                validator.validateRequestSecurity(
                        actualRules,
                        policies
                );


        System.out.println(
                "\n=== FULL RUNTIME POLICY VALIDATION ==="
        );

        for (RequestSecurityRule rule : actualRules) {
            System.out.println(
                    rule.getHttpMethod()
                            + ":"
                            + rule.getPattern()
                            + " -> "
                            + rule.getAccessType()
                            + " -> "
                            + rule.getRoles()
            );
        }

        for (ValidationResult result : results) {
            System.out.println(
                    result.getEndpoint()
                            + " -> "
                            + result.getViolationType()
                            + " -> "
                            + result.getSeverity()
            );
        }


        assertTrue(
                results.isEmpty(),
                "Expected runtime Spring Security to match YAML policy"
        );
    }

    /*
     * ====================================================
     * Helper method for loading:
     *
     * src/test/resources/security-policy-test.yml
     * ====================================================
     */
    private List<ApiPolicy> loadPolicies() {

        InputStream inputStream =
                getClass()
                        .getClassLoader()
                        .getResourceAsStream(
                                "security-policy-test.yml"
                        );


        assertNotNull(
                inputStream,
                "security-policy-test.yml was not found "
                        + "in src/test/resources"
        );


        PolicyLoader loader =
                new PolicyLoader();


        return loader.load(
                inputStream
        );
    }


    /*
     * ====================================================
     * Test application configuration.
     *
     * IMPORTANT:
     *
     * This represents a generic consumer application's
     * Spring Security configuration.
     *
     * The starter itself must NOT contain these rules.
     * ====================================================
     */
    @Configuration
    @EnableWebMvc
    @EnableAutoConfiguration
    @Import(TestController.class)
    static class TestConfiguration {


        @Bean
        SecurityFilterChain securityFilterChain(
                HttpSecurity http)
                throws Exception {


            http
                    .csrf(
                            csrf ->
                                    csrf.disable()
                    )


                    .authorizeHttpRequests(
                            authorization ->
                                    authorization


                                            /*
                                             * Public endpoint
                                             */
                                            .requestMatchers(
                                                    "/api/test/public"
                                            )
                                            .permitAll()


                                            /*
                                             * Everything else under
                                             * /api/test/**
                                             * requires ADMIN.
                                             */
                                            .requestMatchers(
                                                    "/api/test/**"
                                            )
                                            .hasRole(
                                                    "ADMIN"
                                            )


                                            /*
                                             * Generic fallback.
                                             */
                                            .anyRequest()
                                            .authenticated()
                    );


            return http.build();
        }
    }
}