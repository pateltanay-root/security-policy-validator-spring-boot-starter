package com.research.securitypolicy.autoconfigure;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.research.securitypolicy.analyzer.AuthorizationRequestFactory;
import com.research.securitypolicy.analyzer.DefaultRequestSecurityAnalyzer;
import com.research.securitypolicy.analyzer.RequestAuthorizationEvaluator;
import com.research.securitypolicy.analyzer.RequestSecurityAnalyzer;
import com.research.securitypolicy.analyzer.SecurityFilterChainAnalyzer;
import com.research.securitypolicy.config.SecurityPolicyValidatorProperties;
import com.research.securitypolicy.loader.PolicyLoader;
import com.research.securitypolicy.reporter.ConsoleViolationReporter;
import com.research.securitypolicy.reporter.ViolationReporter;
import com.research.securitypolicy.resolver.DefaultEffectiveSecurityResolver;
import com.research.securitypolicy.resolver.EffectiveSecurityResolver;
import com.research.securitypolicy.runner.SecurityPolicyValidationRunner;
import com.research.securitypolicy.scanner.EndpointScanner;
import com.research.securitypolicy.validator.SecurityPolicyValidator;

@AutoConfiguration
@EnableConfigurationProperties(
        SecurityPolicyValidatorProperties.class
)
public class SecurityPolicyAutoConfiguration {


    /*
     * ==========================================
     * POLICY LOADER
     * ==========================================
     */

    @Bean
    @ConditionalOnMissingBean
    public PolicyLoader policyLoader() {

        return new PolicyLoader();
    }


    /*
     * ==========================================
     * EFFECTIVE SECURITY RESOLVER
     * ==========================================
     */

    @Bean
    @ConditionalOnMissingBean(
            EffectiveSecurityResolver.class
    )
    public EffectiveSecurityResolver
            effectiveSecurityResolver() {

        return new DefaultEffectiveSecurityResolver();
    }


    /*
     * ==========================================
     * ENDPOINT SCANNER
     * ==========================================
     */

    @Bean
    @ConditionalOnMissingBean
    public EndpointScanner endpointScanner(
            RequestMappingHandlerMapping handlerMapping) {

        return new EndpointScanner(
                handlerMapping
        );
    }


    /*
     * ==========================================
     * SECURITY FILTER CHAIN ANALYZER
     * ==========================================
     */

    @Bean
    @ConditionalOnBean(FilterChainProxy.class)
    @ConditionalOnMissingBean(
            SecurityFilterChainAnalyzer.class
    )
    public SecurityFilterChainAnalyzer
            securityFilterChainAnalyzer(
                    FilterChainProxy filterChainProxy) {

        return new SecurityFilterChainAnalyzer(
                filterChainProxy
        );
    }


    /*
     * ==========================================
     * REQUEST AUTHORIZATION EVALUATOR
     * ==========================================
     */

    @Bean
    @ConditionalOnBean(
            SecurityFilterChainAnalyzer.class
    )
    @ConditionalOnMissingBean(
            RequestAuthorizationEvaluator.class
    )
    public RequestAuthorizationEvaluator
            requestAuthorizationEvaluator(
                    SecurityFilterChainAnalyzer chainAnalyzer) {

        return new RequestAuthorizationEvaluator(
                chainAnalyzer.getAuthorizationFilter()
        );
    }


    /*
     * ==========================================
     * REQUEST SECURITY ANALYZER
     * ==========================================
     *
     * Only create the real analyzer when an
     * AuthorizationRequestFactory bean exists.
     *
     * This prevents Spring from failing startup
     * when the runtime request factory is absent.
     */

    @Bean
    @ConditionalOnBean(
            AuthorizationRequestFactory.class
    )
    @ConditionalOnMissingBean(
            RequestSecurityAnalyzer.class
    )
    public RequestSecurityAnalyzer
            requestSecurityAnalyzer(
                    ObjectProvider<FilterChainProxy>
                            filterChainProxyProvider,
                    AuthorizationRequestFactory
                            requestFactory) {

        FilterChainProxy filterChainProxy =
                filterChainProxyProvider
                        .getIfAvailable();


        /*
         * If Spring Security is not configured,
         * return an analyzer that produces no
         * runtime request results.
         */
        if (filterChainProxy == null) {

            return endpoints ->
                    java.util.List.of();
        }


        SecurityFilterChainAnalyzer chainAnalyzer =
                new SecurityFilterChainAnalyzer(
                        filterChainProxy
                );


        RequestAuthorizationEvaluator evaluator =
                new RequestAuthorizationEvaluator(
                        chainAnalyzer
                                .getAuthorizationFilter()
                );


        return new DefaultRequestSecurityAnalyzer(
                evaluator,
                requestFactory
        );
    }


    /*
     * ==========================================
     * SECURITY POLICY VALIDATOR
     * ==========================================
     */

    @Bean
    @ConditionalOnMissingBean
    public SecurityPolicyValidator
            securityPolicyValidator() {

        return new SecurityPolicyValidator();
    }


    /*
     * ==========================================
     * VIOLATION REPORTER
     * ==========================================
     */

    @Bean
    @ConditionalOnMissingBean(
            ViolationReporter.class
    )
    public ViolationReporter
            violationReporter() {

        return new ConsoleViolationReporter();
    }


    /*
     * ==========================================
     * VALIDATION RUNNER
     * ==========================================
     *
     * RequestSecurityAnalyzer is optional.
     *
     * If one exists, use it.
     * Otherwise use a local no-op analyzer.
     */

    @Bean
    @ConditionalOnMissingBean
    public SecurityPolicyValidationRunner
            securityPolicyValidationRunner(
                    EndpointScanner endpointScanner,
                    PolicyLoader policyLoader,
                    SecurityPolicyValidator validator,
                    ObjectProvider<RequestSecurityAnalyzer>
                            requestSecurityAnalyzerProvider,
                    ViolationReporter reporter,
                    SecurityPolicyValidatorProperties properties,
                    ResourceLoader resourceLoader) {


        RequestSecurityAnalyzer
                requestSecurityAnalyzer =
                        requestSecurityAnalyzerProvider
                                .getIfAvailable(
                                        () ->
                                                endpoints ->
                                                        java.util.List.of()
                                );


        return new SecurityPolicyValidationRunner(
                endpointScanner,
                policyLoader,
                validator,
                requestSecurityAnalyzer,
                reporter,
                properties,
                resourceLoader
        );
    }
}