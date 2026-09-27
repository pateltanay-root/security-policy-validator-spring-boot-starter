package com.research.securitypolicy.autoconfigure;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import jakarta.servlet.ServletContext;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.research.securitypolicy.analyzer.AuthorizationRequestFactory;
import com.research.securitypolicy.analyzer.DefaultRequestSecurityAnalyzer;
import com.research.securitypolicy.analyzer.RequestSecurityAnalyzer;
import com.research.securitypolicy.analyzer.SimpleAuthorizationRequestFactory;

@SpringBootTest(
        classes =
                SecurityPolicyAutoConfigurationWithSecurityTest
                        .TestConfiguration.class,
        properties = {
                "security-policy-validator.enabled=false"
        }
)
class SecurityPolicyAutoConfigurationWithSecurityTest {

    @Autowired
    private RequestSecurityAnalyzer
            requestSecurityAnalyzer;


    @Test
    void shouldCreateRealRequestSecurityAnalyzerWhenSpringSecurityExists() {

        assertNotNull(
                requestSecurityAnalyzer
        );

        assertInstanceOf(
                DefaultRequestSecurityAnalyzer.class,
                requestSecurityAnalyzer
        );
    }


    @Configuration
    @EnableWebMvc
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


        @Bean
        AuthorizationRequestFactory
                authorizationRequestFactory(
                        ServletContext servletContext) {

            return new SimpleAuthorizationRequestFactory(
                    servletContext
            );
        }
    }
}