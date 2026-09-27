package com.research.securitypolicy.source;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

class ControllerSourceScannerTest {

    @Test
    void shouldFindSpringControllerFiles()
            throws Exception {

        Path project =
                Files.createTempDirectory(
                        "controller-source-scanner-"
                );

        Path controller =
                project.resolve(
                        "PatientController.java"
                );

        Path service =
                project.resolve(
                        "PatientService.java"
                );

        Files.writeString(
                controller,
                """
                package com.example;

                import org.springframework.web.bind.annotation.RestController;

                @RestController
                public class PatientController {
                }
                """
        );

        Files.writeString(
                service,
                """
                package com.example;

                public class PatientService {
                }
                """
        );

        ControllerSourceScanner scanner =
                new ControllerSourceScanner();

        List<Path> controllers =
                scanner.findControllerFiles(
                        List.of(
                                controller,
                                service
                        )
                );

        assertEquals(
                1,
                controllers.size()
        );

        assertEquals(
                controller,
                controllers.get(0)
        );
    }
}