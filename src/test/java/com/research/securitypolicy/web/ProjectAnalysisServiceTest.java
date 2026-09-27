package com.research.securitypolicy.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

class ProjectAnalysisServiceTest {

    @Test
    void shouldAnalyzeUploadedProject()
            throws Exception {

        MockMultipartFile projectZip =
                new MockMultipartFile(
                        "project",
                        "demo.zip",
                        "application/zip",
                        createTestProjectZip()
                );


        String yaml =
                """
                policies:
                  - method: DELETE
                    endpoint: /api/patients/{id}
                    roles:
                      - ADMIN
                """;


        MockMultipartFile policyFile =
                new MockMultipartFile(
                        "policy",
                        "security-policy.yml",
                        "application/x-yaml",
                        yaml.getBytes(
                                StandardCharsets.UTF_8
                        )
                );


        ProjectAnalysisService service =
                new ProjectAnalysisService();


        ProjectAnalysisReport report =
                service.analyze(
                        projectZip,
                        policyFile
                );


        assertNotNull(
                report
        );

        assertNotNull(
                report.getSummary()
        );

        assertNotNull(
                report.getViolations()
        );


        assertEquals(
                1,
                report
                        .getSummary()
                        .getControllers()
        );


        assertEquals(
                1,
                report
                        .getSummary()
                        .getEndpoints()
        );


        assertEquals(
                1,
                report
                        .getSummary()
                        .getPolicies()
        );


        assertTrue(
                report
                        .getSummary()
                        .getJavaFiles() >= 1
        );
    }


    @Test
    void shouldRejectEmptyProjectZip() {

        MockMultipartFile emptyProject =
                new MockMultipartFile(
                        "project",
                        "demo.zip",
                        "application/zip",
                        new byte[0]
                );


        MockMultipartFile policy =
                new MockMultipartFile(
                        "policy",
                        "security-policy.yml",
                        "application/x-yaml",
                        """
                        policies: []
                        """
                        .getBytes(
                                StandardCharsets.UTF_8
                        )
                );


        ProjectAnalysisService service =
                new ProjectAnalysisService();


        assertThrows(
                IllegalArgumentException.class,
                () ->
                        service.analyze(
                                emptyProject,
                                policy
                        )
        );
    }


    @Test
    void shouldRejectEmptyPolicyFile()
            throws Exception {

        MockMultipartFile project =
                new MockMultipartFile(
                        "project",
                        "demo.zip",
                        "application/zip",
                        createTestProjectZip()
                );


        MockMultipartFile emptyPolicy =
                new MockMultipartFile(
                        "policy",
                        "security-policy.yml",
                        "application/x-yaml",
                        new byte[0]
                );


        ProjectAnalysisService service =
                new ProjectAnalysisService();


        assertThrows(
                IllegalArgumentException.class,
                () ->
                        service.analyze(
                                project,
                                emptyPolicy
                        )
        );
    }


    private byte[] createTestProjectZip()
            throws Exception {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();


        try (ZipOutputStream zip =
                     new ZipOutputStream(output)) {

            zip.putNextEntry(
                    new ZipEntry(
                            "demo/src/main/java/"
                                    + "com/example/"
                                    + "PatientController.java"
                    )
            );


            zip.write(
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
                    .getBytes(
                            StandardCharsets.UTF_8
                    )
            );


            zip.closeEntry();


            zip.putNextEntry(
                    new ZipEntry(
                            "demo/pom.xml"
                    )
            );


            zip.write(
                    """
                    <project>
                    </project>
                    """
                    .getBytes(
                            StandardCharsets.UTF_8
                    )
            );


            zip.closeEntry();
        }


        return output.toByteArray();
    }
}