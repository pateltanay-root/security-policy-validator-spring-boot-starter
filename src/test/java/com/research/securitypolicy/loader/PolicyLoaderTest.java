package com.research.securitypolicy.loader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.research.securitypolicy.policy.ApiPolicy;

class PolicyLoaderTest {

    @Test
    void shouldLoadPoliciesFromYaml() {

        InputStream inputStream =
                getClass()
                        .getClassLoader()
                        .getResourceAsStream(
                                "security-policy-test.yml"
                        );

        assertNotNull(
                inputStream,
                "security-policy-test.yml not found"
        );

        PolicyLoader loader =
                new PolicyLoader();

        List<ApiPolicy> policies =
                loader.load(inputStream);

        /*
         * Current YAML contains 7 policies.
         */
        assertEquals(
                7,
                policies.size()
        );


        /*
         * GET /api/test/public
         */
        ApiPolicy publicPolicy =
                findPolicy(
                        policies,
                        "GET",
                        "/api/test/public"
                );

        assertNotNull(publicPolicy);

        assertEquals(
                "PUBLIC",
                publicPolicy.getAccess()
        );

        assertTrue(
                publicPolicy.getRoles().isEmpty()
        );


        /*
         * PUT /api/test/{id}
         */
        ApiPolicy updatePolicy =
                findPolicy(
                        policies,
                        "PUT",
                        "/api/test/{id}"
                );

        assertNotNull(updatePolicy);

        assertEquals(
                "ROLE_BASED",
                updatePolicy.getAccess()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "MANAGER"
                ),
                updatePolicy.getRoles()
        );


        /*
         * DELETE /api/test/{id}
         */
        ApiPolicy deletePolicy =
                findPolicy(
                        policies,
                        "DELETE",
                        "/api/test/{id}"
                );

        assertNotNull(deletePolicy);

        assertEquals(
                List.of("ADMIN"),
                deletePolicy.getRoles()
        );


        /*
         * @Secured endpoint
         */
        ApiPolicy securedPolicy =
                findPolicy(
                        policies,
                        "GET",
                        "/api/test/secured"
                );

        assertNotNull(securedPolicy);

        assertEquals(
                List.of(
                        "ADMIN",
                        "MANAGER"
                ),
                securedPolicy.getRoles()
        );


        /*
         * @RolesAllowed endpoint
         */
        ApiPolicy rolesAllowedPolicy =
                findPolicy(
                        policies,
                        "GET",
                        "/api/test/roles-allowed"
                );

        assertNotNull(rolesAllowedPolicy);

        assertEquals(
                List.of(
                        "ADMIN",
                        "AUDITOR"
                ),
                rolesAllowedPolicy.getRoles()
        );


        /*
         * Class-level USER
         */
        ApiPolicy classDefaultPolicy =
                findPolicy(
                        policies,
                        "GET",
                        "/api/class-test/default"
                );

        assertNotNull(classDefaultPolicy);

        assertEquals(
                List.of("USER"),
                classDefaultPolicy.getRoles()
        );


        /*
         * Method-level ADMIN override
         */
        ApiPolicy classAdminPolicy =
                findPolicy(
                        policies,
                        "GET",
                        "/api/class-test/admin"
                );

        assertNotNull(classAdminPolicy);

        assertEquals(
                List.of("ADMIN"),
                classAdminPolicy.getRoles()
        );
    }


    private ApiPolicy findPolicy(
            List<ApiPolicy> policies,
            String method,
            String endpoint) {

        return policies.stream()

                .filter(policy ->
                        method.equalsIgnoreCase(
                                policy.getMethod()
                        )
                )

                .filter(policy ->
                        endpoint.equals(
                                policy.getEndpoint()
                        )
                )

                .findFirst()
                .orElse(null);
    }
}