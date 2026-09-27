package com.research.securitypolicy.analyzer;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.mock.web.MockHttpServletRequest;

import com.research.securitypolicy.model.EndpointDefinition;

public class SimpleAuthorizationRequestFactory
        implements AuthorizationRequestFactory {

    private final ServletContext servletContext;

    private final EndpointPathResolver pathResolver;


    public SimpleAuthorizationRequestFactory(
            ServletContext servletContext) {

        if (servletContext == null) {
            throw new IllegalArgumentException(
                    "ServletContext must not be null"
            );
        }

        this.servletContext = servletContext;
        this.pathResolver =
                new EndpointPathResolver();
    }


    @Override
    public HttpServletRequest create(
            EndpointDefinition endpoint) {

        if (endpoint == null) {
            throw new IllegalArgumentException(
                    "Endpoint must not be null"
            );
        }

        String requestPath =
                pathResolver.resolve(
                        endpoint.getPath()
                );

        MockHttpServletRequest request =
                new MockHttpServletRequest(
                        servletContext
                );

        request.setMethod(
                endpoint.getHttpMethod()
        );

        request.setContextPath("");

        request.setRequestURI(
                requestPath
        );

        /*
         * Important for MvcRequestMatcher.
         */
        request.setServletPath(
                requestPath
        );

        request.setPathInfo(null);

        return request;
    }
}