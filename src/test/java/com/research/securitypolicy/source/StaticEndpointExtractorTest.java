package com.research.securitypolicy.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.research.securitypolicy.model.EndpointDefinition;

class StaticEndpointExtractorTest {

    @Test
    void shouldExtractEndpointAndRoleFromControllerSource()
            throws Exception {

        Path controllerFile =
                Files.createTempFile(
                        "PatientController",
                        ".java"
                );

        Files.writeString(
                controllerFile,
                """
                package com.example;

                import org.springframework.security.access.prepost.PreAuthorize;
                import org.springframework.web.bind.annotation.DeleteMapping;
                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                @RequestMapping("/api/patients")
                public class PatientController {

                    @DeleteMapping("/{id}")
                    @PreAuthorize("hasRole('ADMIN')")
                    public void deletePatient() {
                    }
                }
                """
        );

        StaticEndpointExtractor extractor =
                new StaticEndpointExtractor();

        List<EndpointDefinition> endpoints =
                extractor.extract(
                        controllerFile
                );

        assertEquals(
                1,
                endpoints.size()
        );

        EndpointDefinition endpoint =
                endpoints.get(0);

        assertEquals(
                "DELETE",
                endpoint.getHttpMethod()
        );

        assertEquals(
                "/api/patients/{id}",
                endpoint.getPath()
        );

        assertEquals(
                "hasRole('ADMIN')",
                endpoint.getAuthorizationExpression()
        );

        assertEquals(
                List.of("ADMIN"),
                endpoint.getRoles()
        );
    }


    @Test
    void shouldExtractPublicEndpointWithoutSecurityAnnotation()
            throws Exception {

        Path controllerFile =
                Files.createTempFile(
                        "PublicController",
                        ".java"
                );

        Files.writeString(
                controllerFile,
                """
                package com.example;

                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RequestMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                @RequestMapping("/api/public")
                public class PublicController {

                    @GetMapping("/status")
                    public String status() {
                        return "OK";
                    }
                }
                """
        );

        StaticEndpointExtractor extractor =
                new StaticEndpointExtractor();

        List<EndpointDefinition> endpoints =
                extractor.extract(
                        controllerFile
                );

        assertEquals(
                1,
                endpoints.size()
        );

        EndpointDefinition endpoint =
                endpoints.get(0);

        assertEquals(
                "GET",
                endpoint.getHttpMethod()
        );

        assertEquals(
                "/api/public/status",
                endpoint.getPath()
        );

        assertNull(
                endpoint.getAuthorizationExpression()
        );

        assertEquals(
                List.of(),
                endpoint.getRoles()
        );
    }


    @Test
    void shouldExtractSecuredRoles()
            throws Exception {

        Path controllerFile =
                Files.createTempFile(
                        "AdminController",
                        ".java"
                );

        Files.writeString(
                controllerFile,
                """
                package com.example;

                import org.springframework.security.access.annotation.Secured;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class AdminController {

                    @GetMapping("/api/admin")
                    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
                    public void admin() {
                    }
                }
                """
        );

        StaticEndpointExtractor extractor =
                new StaticEndpointExtractor();

        List<EndpointDefinition> endpoints =
                extractor.extract(
                        controllerFile
                );

        EndpointDefinition endpoint =
                endpoints.get(0);

        assertEquals(
                "GET",
                endpoint.getHttpMethod()
        );

        assertEquals(
                "/api/admin",
                endpoint.getPath()
        );

        assertEquals(
                List.of(
                        "ADMIN",
                        "MANAGER"
                ),
                endpoint.getRoles()
        );
    }
}