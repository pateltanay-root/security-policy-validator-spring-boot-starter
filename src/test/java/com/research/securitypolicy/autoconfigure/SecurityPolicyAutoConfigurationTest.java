package com.research.securitypolicy.autoconfigure;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.research.securitypolicy.runner.SecurityPolicyValidationRunner;
import com.research.securitypolicy.scanner.EndpointScanner;
import com.research.securitypolicy.scanner.TestController;

@SpringBootTest(
        classes =
                SecurityPolicyAutoConfigurationTest
                        .TestConfiguration.class,
        properties = {
                "security-policy-validator.enabled=true",
                "security-policy-validator.policy-location=classpath:security-policy-test.yml"
        }
)
class SecurityPolicyAutoConfigurationTest {

    @Autowired
    private EndpointScanner endpointScanner;

    @Autowired
    private SecurityPolicyValidationRunner runner;


    @Test
    void shouldAutoConfigureSecurityPolicyValidator() {

        assertNotNull(
                endpointScanner
        );

        assertNotNull(
                runner
        );
    }


    @Configuration
    @EnableWebMvc
    @EnableAutoConfiguration
    @Import(TestController.class)
    static class TestConfiguration {
    }
}