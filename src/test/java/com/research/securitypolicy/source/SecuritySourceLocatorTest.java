package com.research.securitypolicy.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.research.securitypolicy.model.EndpointDefinition;


class SecuritySourceLocatorTest {

    @Test
    void shouldLocateControllerMethodSource()
            throws Exception {

        Path project =
                Files.createTempDirectory(
                        "security-source-locator-"
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


        Method method =
                SampleController.class
                        .getDeclaredMethod(
                                "deleteItem"
                        );


        EndpointDefinition endpoint =
                new EndpointDefinition();

        endpoint.setHttpMethod(
                "DELETE"
        );

        endpoint.setPath(
                "/api/items/{id}"
        );

        endpoint.setControllerClass(
                SampleController.class
        );

        endpoint.setControllerMethod(
                method
        );


        SecuritySourceLocator locator =
                new SecuritySourceLocator();


        Optional<SecuritySourceLocation> result =
                locator.locate(
                        project,
                        endpoint
                );


        assertTrue(
                result.isPresent()
        );


        SecuritySourceLocation location =
                result.get();


        assertEquals(
                "SampleController",
                location.getClassName()
        );

        assertEquals(
                "deleteItem",
                location.getMethodName()
        );

        assertTrue(
                location.getFilePath()
                        .endsWith(
                                "SampleController.java"
                        )
        );

        assertTrue(
                location.getLineNumber() > 0
        );
    }


    /*
     * Small test controller class used only to provide
     * reflection metadata for EndpointDefinition.
     */
    static class SampleController {

        public void deleteItem() {
        }
    }
}