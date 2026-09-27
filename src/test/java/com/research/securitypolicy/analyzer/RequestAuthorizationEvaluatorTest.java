package com.research.securitypolicy.analyzer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootTest(
        classes =
                RequestAuthorizationEvaluatorTest.TestConfiguration.class,
        properties = {
                "security-policy-validator.enabled=false"
        }
)
class RequestAuthorizationEvaluatorTest {

    @Autowired
    private FilterChainProxy filterChainProxy;


    @Test
    void shouldEvaluateRealRequestAuthorizationRules() {

        /*
         * =====================================================
         * 1. Obtain Spring Security AuthorizationFilter
         * =====================================================
         */

        assertNotNull(filterChainProxy);

        SecurityFilterChainAnalyzer chainAnalyzer =
                new SecurityFilterChainAnalyzer(
                        filterChainProxy
                );

        assertNotNull(
                chainAnalyzer.getAuthorizationFilter()
        );


        RequestAuthorizationEvaluator evaluator =
                new RequestAuthorizationEvaluator(
                        chainAnalyzer
                                .getAuthorizationFilter()
                );


        /*
         * =====================================================
         * 2. Create test identities
         * =====================================================
         */

        Authentication anonymous =
                new AnonymousAuthenticationToken(
                        "test-key",
                        "anonymousUser",
                        List.of(
                                new SimpleGrantedAuthority(
                                        "ROLE_ANONYMOUS"
                                )
                        )
                );


        Authentication user =
                UsernamePasswordAuthenticationToken
                        .authenticated(
                                "user",
                                "password",
                                List.of(
                                        new SimpleGrantedAuthority(
                                                "ROLE_USER"
                                        )
                                )
                        );


        Authentication admin =
                UsernamePasswordAuthenticationToken
                        .authenticated(
                                "admin",
                                "password",
                                List.of(
                                        new SimpleGrantedAuthority(
                                                "ROLE_ADMIN"
                                        )
                                )
                        );


        /*
         * =====================================================
         * 3. PUBLIC ENDPOINT
         *
         * /api/public/**
         * → permitAll()
         * =====================================================
         */

        assertTrue(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/public/test"
                        ),
                        anonymous
                )
        );

        assertTrue(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/public/test"
                        ),
                        user
                )
        );

        assertTrue(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/public/test"
                        ),
                        admin
                )
        );


        /*
         * =====================================================
         * 4. ADMIN ENDPOINT
         *
         * /api/admin/**
         * → hasRole("ADMIN")
         * =====================================================
         */

        assertFalse(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/admin/users"
                        ),
                        anonymous
                )
        );


        assertFalse(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/admin/users"
                        ),
                        user
                )
        );


        assertTrue(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/admin/users"
                        ),
                        admin
                )
        );


        /*
         * =====================================================
         * 5. AUTHENTICATED ENDPOINT
         *
         * anyRequest()
         * → authenticated()
         * =====================================================
         */

        assertFalse(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/profile"
                        ),
                        anonymous
                )
        );


        assertTrue(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/profile"
                        ),
                        user
                )
        );


        assertTrue(
                evaluator.isGranted(
                        request(
                                "GET",
                                "/api/profile"
                        ),
                        admin
                )
        );
    }


    /*
     * Creates a mock servlet request only for testing.
     *
     * Production code remains independent from
     * Spring's MockHttpServletRequest.
     */
    private MockHttpServletRequest request(
            String method,
            String path) {

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.setMethod(method);
        request.setRequestURI(path);
        request.setServletPath(path);

        return request;
    }


    /*
     * =========================================================
     * TEST-ONLY SPRING SECURITY CONFIGURATION
     * =========================================================
     *
     * /api/public/** → PUBLIC
     *
     * /api/admin/**  → ROLE_ADMIN
     *
     * everything else → AUTHENTICATED
     */
    @Configuration
    @EnableAutoConfiguration
    static class TestConfiguration {

        @Bean
        SecurityFilterChain securityFilterChain(
                HttpSecurity http)
                throws Exception {

            http
                    .authorizeHttpRequests(
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