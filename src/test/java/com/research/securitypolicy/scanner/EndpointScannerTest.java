package com.research.securitypolicy.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.SecuritySource;

@SpringBootTest(
        classes = EndpointScannerTest.TestConfiguration.class,
        properties = {
                "security-policy-validator.enabled=false"
        }
)
class EndpointScannerTest {

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    @Test
    void shouldDiscoverAllSupportedSecurityAnnotations() {

        EndpointScanner scanner =
                new EndpointScanner(handlerMapping);

        List<EndpointDefinition> endpoints =
                scanner.scanEndpoints();

        System.out.println(
                "\n=== DISCOVERED ENDPOINTS ==="
        );

        for (EndpointDefinition endpoint : endpoints) {

            System.out.println(
                    endpoint.getEndpointKey()
                            + " -> "
                            + endpoint.getAuthorizationExpression()
                            + " -> "
                            + endpoint.getRoles()
                            + " -> "
                            + endpoint.getAuthorization()
                                    .getAccessType()
                            + " -> "
                            + endpoint.getAuthorization()
                                    .getSecuritySource()
            );
        }


        /*
         * =====================================================
         * CLASS-LEVEL @PreAuthorize
         * =====================================================
         *
         * Controller:
         *
         * @PreAuthorize("hasRole('USER')")
         *
         * Method itself has no security annotation,
         * therefore the class rule should be used.
         */

        EndpointDefinition classLevelEndpoint =
                findEndpoint(
                        endpoints,
                        "GET",
                        "/api/class-test/default"
                );

        assertNotNull(classLevelEndpoint);

        assertNotNull(
                classLevelEndpoint.getAuthorization()
        );

        assertEquals(
                "hasRole('USER')",
                classLevelEndpoint
                        .getAuthorizationExpression()
        );

        assertEquals(
                List.of("USER"),
                classLevelEndpoint.getRoles()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                classLevelEndpoint
                        .getAuthorization()
                        .getAccessType()
        );

        assertEquals(
                SecuritySource.PRE_AUTHORIZE,
                classLevelEndpoint
                        .getAuthorization()
                        .getSecuritySource()
        );

        assertEquals(
                List.of("USER"),
                classLevelEndpoint
                        .getAuthorization()
                        .getRoles()
        );


        /*
         * =====================================================
         * METHOD-LEVEL @PreAuthorize OVERRIDE
         * =====================================================
         *
         * Class:
         *
         * @PreAuthorize("hasRole('USER')")
         *
         * Method:
         *
         * @PreAuthorize("hasRole('ADMIN')")
         *
         * Method-level security should take precedence.
         */

        EndpointDefinition adminEndpoint =
                findEndpoint(
                        endpoints,
                        "GET",
                        "/api/class-test/admin"
                );

        assertNotNull(adminEndpoint);

        assertNotNull(
                adminEndpoint.getAuthorization()
        );

        assertEquals(
                "hasRole('ADMIN')",
                adminEndpoint
                        .getAuthorizationExpression()
        );

        assertEquals(
                List.of("ADMIN"),
                adminEndpoint.getRoles()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                adminEndpoint
                        .getAuthorization()
                        .getAccessType()
        );

        assertEquals(
                SecuritySource.PRE_AUTHORIZE,
                adminEndpoint
                        .getAuthorization()
                        .getSecuritySource()
        );

        assertEquals(
                List.of("ADMIN"),
                adminEndpoint
                        .getAuthorization()
                        .getRoles()
        );


        /*
         * =====================================================
         * @Secured
         * =====================================================
         */

        EndpointDefinition securedEndpoint =
                findEndpoint(
                        endpoints,
                        "GET",
                        "/api/test/secured"
                );

        assertNotNull(securedEndpoint);

        assertNotNull(
                securedEndpoint.getAuthorization()
        );

        assertEquals(
                "SECURED:ROLE_ADMIN,ROLE_MANAGER",
                securedEndpoint
                        .getAuthorizationExpression()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "MANAGER"
                ),
                securedEndpoint.getRoles()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                securedEndpoint
                        .getAuthorization()
                        .getAccessType()
        );

        assertEquals(
                SecuritySource.SECURED,
                securedEndpoint
                        .getAuthorization()
                        .getSecuritySource()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "MANAGER"
                ),
                securedEndpoint
                        .getAuthorization()
                        .getRoles()
        );


        /*
         * =====================================================
         * @RolesAllowed
         * =====================================================
         */

        EndpointDefinition rolesAllowedEndpoint =
                findEndpoint(
                        endpoints,
                        "GET",
                        "/api/test/roles-allowed"
                );

        assertNotNull(rolesAllowedEndpoint);

        assertNotNull(
                rolesAllowedEndpoint.getAuthorization()
        );

        assertEquals(
                "ROLES_ALLOWED:ADMIN,AUDITOR",
                rolesAllowedEndpoint
                        .getAuthorizationExpression()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "AUDITOR"
                ),
                rolesAllowedEndpoint.getRoles()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                rolesAllowedEndpoint
                        .getAuthorization()
                        .getAccessType()
        );

        assertEquals(
                SecuritySource.ROLES_ALLOWED,
                rolesAllowedEndpoint
                        .getAuthorization()
                        .getSecuritySource()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "AUDITOR"
                ),
                rolesAllowedEndpoint
                        .getAuthorization()
                        .getRoles()
        );


        /*
         * =====================================================
         * NO METHOD-SECURITY ANNOTATION
         * =====================================================
         *
         * From the method-security perspective,
         * this endpoint is currently PUBLIC.
         *
         * Later SecurityFilterChain analysis may
         * provide request-level protection.
         */

        EndpointDefinition publicEndpoint =
                findEndpoint(
                        endpoints,
                        "GET",
                        "/api/test/public"
                );

        assertNotNull(publicEndpoint);

        assertNotNull(
                publicEndpoint.getAuthorization()
        );

        assertNull(
                publicEndpoint
                        .getAuthorizationExpression()
        );

        assertTrue(
                publicEndpoint
                        .getRoles()
                        .isEmpty()
        );

        assertEquals(
                AccessType.PUBLIC,
                publicEndpoint
                        .getAuthorization()
                        .getAccessType()
        );

        assertEquals(
                SecuritySource.NONE,
                publicEndpoint
                        .getAuthorization()
                        .getSecuritySource()
        );

        assertTrue(
                publicEndpoint
                        .getAuthorization()
                        .getRoles()
                        .isEmpty()
        );

        assertNull(
                publicEndpoint
                        .getAuthorization()
                        .getRawExpression()
        );


        /*
         * =====================================================
         * @PreAuthorize hasAnyRole(...)
         * =====================================================
         */

        EndpointDefinition updateEndpoint =
                findEndpoint(
                        endpoints,
                        "PUT",
                        "/api/test/{id}"
                );

        assertNotNull(updateEndpoint);

        assertNotNull(
                updateEndpoint.getAuthorization()
        );

        assertEquals(
                "hasAnyRole('ADMIN','MANAGER')",
                updateEndpoint
                        .getAuthorizationExpression()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "MANAGER"
                ),
                updateEndpoint.getRoles()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                updateEndpoint
                        .getAuthorization()
                        .getAccessType()
        );

        assertEquals(
                SecuritySource.PRE_AUTHORIZE,
                updateEndpoint
                        .getAuthorization()
                        .getSecuritySource()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "MANAGER"
                ),
                updateEndpoint
                        .getAuthorization()
                        .getRoles()
        );

        assertEquals(
                "hasAnyRole('ADMIN','MANAGER')",
                updateEndpoint
                        .getAuthorization()
                        .getRawExpression()
        );


        /*
         * =====================================================
         * @PreAuthorize hasRole(...)
         * =====================================================
         */

        EndpointDefinition deleteEndpoint =
                findEndpoint(
                        endpoints,
                        "DELETE",
                        "/api/test/{id}"
                );

        assertNotNull(deleteEndpoint);

        assertNotNull(
                deleteEndpoint.getAuthorization()
        );

        assertEquals(
                "hasRole('ADMIN')",
                deleteEndpoint
                        .getAuthorizationExpression()
        );

        assertEquals(
                List.of("ADMIN"),
                deleteEndpoint.getRoles()
        );

        assertEquals(
                AccessType.ROLE_BASED,
                deleteEndpoint
                        .getAuthorization()
                        .getAccessType()
        );

        assertEquals(
                SecuritySource.PRE_AUTHORIZE,
                deleteEndpoint
                        .getAuthorization()
                        .getSecuritySource()
        );

        assertEquals(
                List.of("ADMIN"),
                deleteEndpoint
                        .getAuthorization()
                        .getRoles()
        );

        assertEquals(
                "hasRole('ADMIN')",
                deleteEndpoint
                        .getAuthorization()
                        .getRawExpression()
        );
    }


    /*
     * Finds one discovered endpoint using
     * HTTP method + normalized path.
     */
    private EndpointDefinition findEndpoint(
            List<EndpointDefinition> endpoints,
            String httpMethod,
            String path) {

        return endpoints.stream()

                .filter(endpoint ->
                        httpMethod.equals(
                                endpoint.getHttpMethod()
                        )
                )

                .filter(endpoint ->
                        path.equals(
                                endpoint.getPath()
                        )
                )

                .findFirst()
                .orElse(null);
    }


    /*
     * Test-only Spring configuration.
     *
     * This starter does not contain a normal
     * @SpringBootApplication class.
     *
     * We therefore create a minimal Spring MVC
     * context and register our test controllers.
     */
    @Configuration
    @EnableWebMvc
    @EnableAutoConfiguration
    @Import({
            TestController.class,
            ClassLevelSecurityController.class
    })
    static class TestConfiguration {

    }
}