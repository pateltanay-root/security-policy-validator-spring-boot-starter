package com.research.securitypolicy.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.validator.Severity;
import com.research.securitypolicy.validator.ValidationResult;
import com.research.securitypolicy.validator.ViolationType;


class ValidationResultSourceEnricherTest {

    @Test
    void shouldAttachSourceLocationToViolation()
            throws Exception {

        Path project =
                Files.createTempDirectory(
                        "validation-source-enricher-"
                );


        Path controllerFile =
                project.resolve(
                        "src/main/java/"
                        + "com/research/securitypolicy/source/"
                        + "SampleController.java"
                );


        Files.createDirectories(
                controllerFile.getParent()
        );


        Files.writeString(
                controllerFile,
                """
                package com.research.securitypolicy.source;

                import org.springframework.web.bind.annotation.RestController;
                import org.springframework.web.bind.annotation.DeleteMapping;

                @RestController
                public class SampleController {

                    @DeleteMapping("/api/items/{id}")
                    public void deleteItem() {
                    }
                }
                """
        );


        Method controllerMethod =
                SampleController.class
                        .getDeclaredMethod(
                                "deleteItem"
                        );


        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod("DELETE");
        endpoint.setPath("/api/items/{id}");

        endpoint.setControllerClass(
                SampleController.class
        );

        endpoint.setControllerMethod(
                controllerMethod
        );


        ValidationResult violation =
                new ValidationResult(
                        "DELETE:/api/items/{id}",
                        ViolationType.ROLE_MISMATCH,
                        Severity.CRITICAL,
                        "Wrong role configured",
                        "ADMIN",
                        "USER"
                );


        ValidationResultSourceEnricher enricher =
                new ValidationResultSourceEnricher();


        enricher.enrich(
                project,
                List.of(endpoint),
                List.of(violation)
        );


        assertNotNull(
                violation.getSourceLocation()
        );


        assertEquals(
                "SampleController",
                violation
                        .getSourceLocation()
                        .getClassName()
        );


        assertEquals(
                "deleteItem",
                violation
                        .getSourceLocation()
                        .getMethodName()
        );
    }


    static class SampleController {

        public void deleteItem() {
        }
    }
}