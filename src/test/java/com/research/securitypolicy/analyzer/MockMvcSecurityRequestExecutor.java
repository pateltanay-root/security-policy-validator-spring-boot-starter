package com.research.securitypolicy.analyzer;

import java.util.Collections;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.research.securitypolicy.model.EndpointDefinition;

import static org.springframework.security.test.web.servlet.request
        .SecurityMockMvcRequestPostProcessors.user;

import static org.springframework.test.web.servlet.request
        .MockMvcRequestBuilders.request;


public class MockMvcSecurityRequestExecutor
        implements SecurityRequestExecutor {

    private final MockMvc mockMvc;

    private final EndpointPathResolver pathResolver;


    public MockMvcSecurityRequestExecutor(
            MockMvc mockMvc) {

        if (mockMvc == null) {
            throw new IllegalArgumentException(
                    "MockMvc must not be null"
            );
        }

        this.mockMvc = mockMvc;
        this.pathResolver =
                new EndpointPathResolver();
    }


    /*
     * Anonymous request.
     */
    @Override
    public boolean isAllowedAnonymous(
            EndpointDefinition endpoint) {

        MockHttpServletRequestBuilder request =
                createRequest(endpoint);

        return execute(request);
    }


    /*
     * Authenticated user with NO application role.
     *
     * This is important because assigning ROLE_USER
     * automatically could incorrectly classify an
     * endpoint as AUTHENTICATED.
     */
    @Override
    public boolean isAllowedAuthenticated(
            EndpointDefinition endpoint) {

        MockHttpServletRequestBuilder request =
                createRequest(endpoint)
                        .with(
                                user("security-policy-user")
                                        .authorities(
                                                Collections.emptyList()
                                        )
                        );

        return execute(request);
    }


    /*
     * Authenticated request containing the supplied roles.
     */
    @Override
    public boolean isAllowedWithRoles(
            EndpointDefinition endpoint,
            List<String> roles) {

        if (roles == null || roles.isEmpty()) {
            return isAllowedAuthenticated(
                    endpoint
            );
        }

        String[] normalizedRoles =
                roles.stream()
                        .filter(role ->
                                role != null
                                        && !role.isBlank()
                        )
                        .map(this::normalizeRole)
                        .toArray(String[]::new);


        MockHttpServletRequestBuilder request =
                createRequest(endpoint)
                        .with(
                                user("security-policy-role-user")
                                        .roles(
                                                normalizedRoles
                                        )
                        );


        return execute(request);
    }


    /*
     * Convert EndpointDefinition into an actual
     * MockMvc request.
     *
     * Example:
     *
     * DELETE /api/test/{id}
     *
     * becomes:
     *
     * DELETE /api/test/1
     */
    private MockHttpServletRequestBuilder createRequest(
            EndpointDefinition endpoint) {

        if (endpoint == null) {
            throw new IllegalArgumentException(
                    "Endpoint must not be null"
            );
        }


        String method =
                endpoint.getHttpMethod();

        if (method == null || method.isBlank()) {
            throw new IllegalArgumentException(
                    "Endpoint HTTP method must not be blank"
            );
        }


        String path =
                pathResolver.resolve(
                        endpoint.getPath()
                );


        HttpMethod httpMethod =
                HttpMethod.valueOf(
                        method
                                .trim()
                                .toUpperCase()
                );


        return request(
                httpMethod,
                path
        );
    }


    /*
     * Security decision:
     *
     * 401 -> authentication denied
     * 403 -> authorization denied
     *
     * Other status codes mean the request passed
     * Spring Security.
     *
     * For example, 400 could be caused by a missing
     * request body. That is NOT a security denial.
     */
    private boolean execute(
            MockHttpServletRequestBuilder request) {

        try {

            int status =
                    mockMvc.perform(request)
                            .andReturn()
                            .getResponse()
                            .getStatus();


            return status != 401
                    && status != 403;

        } catch (Exception exception) {

            throw new IllegalStateException(
                    "Failed to execute security request",
                    exception
            );
        }
    }


    private String normalizeRole(
            String role) {

        String normalized =
                role
                        .trim()
                        .toUpperCase();


        if (normalized.startsWith("ROLE_")) {

            normalized =
                    normalized.substring(
                            "ROLE_".length()
                    );
        }


        return normalized;
    }
}