package com.research.securitypolicy.analyzer;

import java.util.function.Supplier;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.util.ServletRequestPathUtils;

import jakarta.servlet.http.HttpServletRequest;

public class RequestAuthorizationEvaluator {

    private final AuthorizationFilter authorizationFilter;

    public RequestAuthorizationEvaluator(
            AuthorizationFilter authorizationFilter) {

        if (authorizationFilter == null) {
            throw new IllegalArgumentException(
                    "AuthorizationFilter must not be null"
            );
        }

        this.authorizationFilter =
                authorizationFilter;
    }

    public boolean isGranted(
            HttpServletRequest request,
            Authentication authentication) {

        if (request == null) {
            throw new IllegalArgumentException(
                    "HttpServletRequest must not be null"
            );
        }

        Supplier<Authentication> authenticationSupplier =
                () -> authentication;

        /*
         * Prepare the request path similarly to what
         * Spring MVC / Spring Security normally does
         * before request matcher evaluation.
         */
        if (!ServletRequestPathUtils
                .hasParsedRequestPath(request)) {

            ServletRequestPathUtils
                    .parseAndCache(request);
        }

        var result =
                authorizationFilter
                        .getAuthorizationManager()
                        .authorize(
                                authenticationSupplier,
                                request
                        );

        return result != null
                && result.isGranted();
    }
}