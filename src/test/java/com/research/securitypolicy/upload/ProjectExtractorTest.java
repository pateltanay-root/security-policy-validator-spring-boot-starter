package com.research.securitypolicy.upload;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;

class ProjectExtractorTest {

    @Test
    void shouldExtractSpringBootProjectZip()
            throws Exception {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        try (ZipOutputStream zip =
                     new ZipOutputStream(output)) {

            zip.putNextEntry(
                    new ZipEntry(
                            "demo/src/main/java/com/example/TestController.java"
                    )
            );

            zip.write(
                    """
                    package com.example;

                    public class TestController {
                    }
                    """.getBytes()
            );

            zip.closeEntry();

            zip.putNextEntry(
                    new ZipEntry(
                            "demo/pom.xml"
                    )
            );

            zip.write(
                    "<project></project>".getBytes()
            );

            zip.closeEntry();
        }

        ProjectExtractor extractor =
                new ProjectExtractor();

        Path extractedDirectory =
                extractor.extract(
                        new ByteArrayInputStream(
                                output.toByteArray()
                        )
                );

        Path javaFile =
                extractedDirectory.resolve(
                        "demo/src/main/java/com/example/TestController.java"
                );

        Path pomFile =
                extractedDirectory.resolve(
                        "demo/pom.xml"
                );

        assertTrue(
                Files.exists(javaFile)
        );

        assertTrue(
                Files.exists(pomFile)
        );

        assertEquals(
                "<project></project>",
                Files.readString(pomFile)
        );
    }


    @Test
    void shouldRejectNullInputStream() {

        ProjectExtractor extractor =
                new ProjectExtractor();

        assertThrows(
                IllegalArgumentException.class,
                () -> extractor.extract(null)
        );
    }


    @Test
    void shouldRejectZipSlipAttack()
            throws Exception {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        try (ZipOutputStream zip =
                     new ZipOutputStream(output)) {

            zip.putNextEntry(
                    new ZipEntry(
                            "../../evil.txt"
                    )
            );

            zip.write(
                    "malicious".getBytes()
            );

            zip.closeEntry();
        }

        ProjectExtractor extractor =
                new ProjectExtractor();

        assertThrows(
                Exception.class,
                () ->
                        extractor.extract(
                                new ByteArrayInputStream(
                                        output.toByteArray()
                                )
                        )
        );
    }
}