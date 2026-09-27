package com.research.securitypolicy.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockServletContext;

import com.research.securitypolicy.model.EndpointDefinition;


class SimpleAuthorizationRequestFactoryTest {

    private ServletContext servletContext;

    private SimpleAuthorizationRequestFactory factory;


    @BeforeEach
    void setUp() {

        servletContext =
                new MockServletContext();

        factory =
                new SimpleAuthorizationRequestFactory(
                        servletContext
                );
    }


    /*
     * Basic GET request.
     */
    @Test
    void shouldCreateRequestFromEndpoint() {

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod("GET");
        endpoint.setPath(
                "/api/test/public"
        );


        HttpServletRequest request =
                factory.create(
                        endpoint
                );


        assertNotNull(
                request
        );

        assertEquals(
                "GET",
                request.getMethod()
        );

        assertEquals(
                "/api/test/public",
                request.getRequestURI()
        );

        assertEquals(
                "/api/test/public",
                request.getServletPath()
        );

        assertEquals(
                "",
                request.getContextPath()
        );

        assertNull(
                request.getPathInfo()
        );
    }


    /*
     * Spring MVC path variables must be converted
     * into concrete request values before Spring
     * Security evaluates the request.
     *
     * /api/test/{id}
     *
     * becomes
     *
     * /api/test/1
     */
    @Test
    void shouldResolvePathVariables() {

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod(
                "DELETE"
        );

        endpoint.setPath(
                "/api/test/{id}"
        );


        HttpServletRequest request =
                factory.create(
                        endpoint
                );


        assertEquals(
                "DELETE",
                request.getMethod()
        );

        assertEquals(
                "/api/test/1",
                request.getRequestURI()
        );

        assertEquals(
                "/api/test/1",
                request.getServletPath()
        );
    }


    /*
     * Multiple path variables should also
     * be converted generically.
     */
    @Test
    void shouldResolveMultiplePathVariables() {

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod(
                "GET"
        );

        endpoint.setPath(
                "/api/users/{userId}/orders/{orderId}"
        );


        HttpServletRequest request =
                factory.create(
                        endpoint
                );


        assertEquals(
                "/api/users/1/orders/1",
                request.getRequestURI()
        );

        assertEquals(
                "/api/users/1/orders/1",
                request.getServletPath()
        );
    }


    /*
     * Verify different HTTP methods are retained.
     */
    @Test
    void shouldPreserveHttpMethod() {

        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod(
                "POST"
        );

        endpoint.setPath(
                "/api/test"
        );


        HttpServletRequest request =
                factory.create(
                        endpoint
                );


        assertEquals(
                "POST",
                request.getMethod()
        );
    }


    /*
     * Factory must reject null endpoints.
     */
    @Test
    void shouldRejectNullEndpoint() {

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                factory.create(
                                        null
                                )
                );


        assertEquals(
                "Endpoint must not be null",
                exception.getMessage()
        );
    }


    /*
     * Constructor must reject null ServletContext.
     */
    @Test
    void shouldRejectNullServletContext() {

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                new SimpleAuthorizationRequestFactory(
                                        null
                                )
                );


        assertEquals(
                "ServletContext must not be null",
                exception.getMessage()
        );
    }
}