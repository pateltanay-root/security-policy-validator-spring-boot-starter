package com.research.securitypolicy.source;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

class JavaProjectScannerTest {

    @Test
    void shouldFindJavaFilesRecursively()
            throws Exception {

        Path project =
                Files.createTempDirectory(
                        "java-project-scanner-"
                );

        Path controller =
                project.resolve(
                        "src/main/java/com/example/TestController.java"
                );

        Path service =
                project.resolve(
                        "src/main/java/com/example/TestService.java"
                );

        Path pom =
                project.resolve("pom.xml");

        Files.createDirectories(
                controller.getParent()
        );

        Files.writeString(
                controller,
                "class TestController {}"
        );

        Files.writeString(
                service,
                "class TestService {}"
        );

        Files.writeString(
                pom,
                "<project/>"
        );

        JavaProjectScanner scanner =
                new JavaProjectScanner();

        List<Path> javaFiles =
                scanner.findJavaFiles(project);

        assertEquals(
                2,
                javaFiles.size()
        );
    }
}