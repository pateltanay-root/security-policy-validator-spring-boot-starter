package com.research.securitypolicy.analyzer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@SpringBootTest(
        classes =
                SecurityFilterChainAnalyzerTest.TestConfiguration.class,
        properties = {
                "security-policy-validator.enabled=false"
        }
)
class SecurityFilterChainAnalyzerTest {

    @Autowired
    private FilterChainProxy filterChainProxy;


    @Test
    void shouldDiscoverSecurityFilterChainInfrastructure() {

        /*
         * 1. Spring Security should have created
         * FilterChainProxy.
         */
        assertNotNull(filterChainProxy);


        /*
         * 2. Create our analyzer using the real
         * Spring Security FilterChainProxy.
         */
        SecurityFilterChainAnalyzer analyzer =
                new SecurityFilterChainAnalyzer(
                        filterChainProxy
                );


        /*
         * 3. At least one SecurityFilterChain
         * should exist.
         */
        assertTrue(
                analyzer.getSecurityFilterChainCount() > 0,
                "Expected at least one SecurityFilterChain"
        );


        /*
         * 4. authorizeHttpRequests() should have
         * created an AuthorizationFilter.
         */
        assertTrue(
                analyzer.hasAuthorizationFilter(),
                "Expected AuthorizationFilter in the security chain"
        );


        /*
         * 5. Retrieve the actual AuthorizationFilter.
         */
        AuthorizationFilter authorizationFilter =
                analyzer.getAuthorizationFilter();

        assertNotNull(
                authorizationFilter,
                "Expected AuthorizationFilter"
        );


        /*
         * 6. Verify that Spring Security's
         * AuthorizationManager is available.
         */
        assertNotNull(
                authorizationFilter
                        .getAuthorizationManager(),
                "Expected AuthorizationManager"
        );
    }


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