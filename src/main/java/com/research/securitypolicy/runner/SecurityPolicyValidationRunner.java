package com.research.securitypolicy.runner;

import java.io.InputStream;
import java.util.List;
import java.util.ArrayList;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.research.securitypolicy.analyzer.RequestSecurityAnalyzer;
import com.research.securitypolicy.model.RequestSecurityRule;
import com.research.securitypolicy.config.SecurityPolicyValidatorProperties;
import com.research.securitypolicy.loader.PolicyLoader;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.policy.ApiPolicy;
import com.research.securitypolicy.reporter.ViolationReporter;
import com.research.securitypolicy.scanner.EndpointScanner;
import com.research.securitypolicy.validator.SecurityPolicyValidator;
import com.research.securitypolicy.validator.ValidationResult;

public class SecurityPolicyValidationRunner
        implements ApplicationRunner {

    private final EndpointScanner endpointScanner;
    private final PolicyLoader policyLoader;
    private final SecurityPolicyValidator validator;
    private final ViolationReporter reporter;
    private final SecurityPolicyValidatorProperties properties;
    private final ResourceLoader resourceLoader;
    private final RequestSecurityAnalyzer requestSecurityAnalyzer;

    public SecurityPolicyValidationRunner(
            EndpointScanner endpointScanner,
            PolicyLoader policyLoader,
            SecurityPolicyValidator validator,
            RequestSecurityAnalyzer requestSecurityAnalyzer,
            ViolationReporter reporter,
            SecurityPolicyValidatorProperties properties,
            ResourceLoader resourceLoader) {

        this.endpointScanner = endpointScanner;
        this.policyLoader = policyLoader;
        this.validator = validator;
        this.requestSecurityAnalyzer =
                requestSecurityAnalyzer;
        this.reporter = reporter;
        this.properties = properties;
        this.resourceLoader = resourceLoader;
    }
    
    private boolean hasPolicy(
            RequestSecurityRule rule,
            List<ApiPolicy> policies) {

        if (policies == null) {
            return false;
        }

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

        String ruleKey =
                method + ":" + pattern;

        return policies.stream()
                .anyMatch(policy ->
                        ruleKey.equals(
                                policy.getPolicyKey()
                        )
                );
    }

    @Override
    public void run(ApplicationArguments args)
            throws Exception {

        if (!properties.isEnabled()) {
            System.out.println(
                    "Security Policy Validator is disabled."
            );
            return;
        }

        System.out.println(
                "\n=== SECURITY POLICY VALIDATION STARTED ==="
        );

        Resource resource =
                resourceLoader.getResource(
                        properties.getPolicyLocation()
                );

        if (!resource.exists()) {
            System.out.println(
                "Security policy file not found. Skipping startup validation."
            );
            return;
        }
        
        List<ApiPolicy> policies;

        try (InputStream inputStream =
                     resource.getInputStream()) {

            policies =
                    policyLoader.load(inputStream);
        }

        List<EndpointDefinition> endpoints =
                endpointScanner.scanEndpoints();

        /*
         * Existing method-level validation.
         */
        List<ValidationResult> results =
                new ArrayList<>(
                        validator.validate(
                                endpoints,
                                policies
                        )
                );

        /*
         * Analyze the actual Spring Security
         * request-level configuration.
         */
        List<RequestSecurityRule> requestRules =
                requestSecurityAnalyzer.analyze(
                        endpoints
                );


        /*
         * Only validate request-level security for
         * endpoints that already have a policy.
         *
         * Missing policies are reported by the
         * existing endpoint validator above, so this
         * prevents duplicate MISSING_POLICY results.
         */
        List<RequestSecurityRule> requestRulesWithPolicy =
                requestRules.stream()
                        .filter(rule ->
                                hasPolicy(
                                        rule,
                                        policies
                                )
                        )
                        .toList();

        List<ValidationResult> requestResults =
                validator.validateRequestSecurity(
                        requestRulesWithPolicy,
                        policies
                );

        results.addAll(
                requestResults
        );

        if (results.isEmpty()) {

            System.out.println(
                    "✅ No security policy violations detected."
            );

        } else {

            System.out.println(
                    "❌ Security policy violations detected: "
                    + results.size()
            );

            for (ValidationResult result : results) {
                reporter.report(result);
            }
        }

        System.out.println(
                "=== SECURITY POLICY VALIDATION COMPLETED ===\n"
        );
    }
}