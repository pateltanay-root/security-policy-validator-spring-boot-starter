package com.research.securitypolicy.source;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import com.research.securitypolicy.model.EndpointDefinition;

/**
 * Locates the Java source-code position associated
 * with an EndpointDefinition.
 *
 * Example result:
 *
 * PatientController
 * deletePatient
 * src/main/java/.../PatientController.java
 * line 42
 */
public class SecuritySourceLocator {

    private final JavaProjectScanner projectScanner;

    private final ControllerSourceAnalyzer sourceAnalyzer;


    public SecuritySourceLocator() {

        this.projectScanner =
                new JavaProjectScanner();

        this.sourceAnalyzer =
                new ControllerSourceAnalyzer();
    }


    public SecuritySourceLocator(
            JavaProjectScanner projectScanner,
            ControllerSourceAnalyzer sourceAnalyzer) {

        if (projectScanner == null) {
            throw new IllegalArgumentException(
                    "JavaProjectScanner must not be null"
            );
        }

        if (sourceAnalyzer == null) {
            throw new IllegalArgumentException(
                    "ControllerSourceAnalyzer must not be null"
            );
        }

        this.projectScanner =
                projectScanner;

        this.sourceAnalyzer =
                sourceAnalyzer;
    }


    /**
     * Locate the controller source file and method
     * corresponding to the supplied endpoint.
     *
     * @param projectDirectory extracted Spring Boot project
     * @param endpoint endpoint discovered by the scanner
     * @return source location when found
     */
    public Optional<SecuritySourceLocation> locate(
            Path projectDirectory,
            EndpointDefinition endpoint)
            throws IOException {

        if (projectDirectory == null) {
            throw new IllegalArgumentException(
                    "Project directory must not be null"
            );
        }

        if (endpoint == null) {
            throw new IllegalArgumentException(
                    "Endpoint must not be null"
            );
        }

        /*
         * EndpointScanner already stores the actual
         * controller Class and Method.
         */
        if (endpoint.getControllerClass() == null) {
            return Optional.empty();
        }

        String controllerClassName =
                endpoint
                        .getControllerClass()
                        .getSimpleName();


        String controllerMethodName =
                endpoint.getControllerMethod() == null
                        ? null
                        : endpoint
                                .getControllerMethod()
                                .getName();


        /*
         * Find every Java source file in the
         * extracted application.
         */
        List<Path> javaFiles =
                projectScanner.findJavaFiles(
                        projectDirectory
                );


        for (Path javaFile : javaFiles) {

            /*
             * Fast check first.
             *
             * Usually:
             *
             * PatientController
             *
             * lives in:
             *
             * PatientController.java
             */
            String fileName =
                    javaFile
                            .getFileName()
                            .toString();

            if (!fileName.equals(
                    controllerClassName + ".java"
            )) {
                continue;
            }


            /*
             * Verify using JavaParser that this really
             * contains the expected controller class.
             */
            Optional<String> parsedClassName =
                    sourceAnalyzer
                            .findControllerClassName(
                                    javaFile
                            );

            if (parsedClassName.isEmpty()) {
                continue;
            }

            if (!controllerClassName.equals(
                    parsedClassName.get()
            )) {
                continue;
            }


            /*
             * If no controller method metadata exists,
             * we can still return the controller file.
             */
            if (controllerMethodName == null
                    || controllerMethodName.isBlank()) {

                return Optional.of(
                        new SecuritySourceLocation(
                                controllerClassName,
                                null,
                                buildRelativePath(
                                        projectDirectory,
                                        javaFile
                                ),
                                0
                        )
                );
            }


            /*
             * Locate the method's line number.
             */
            Optional<Integer> lineNumber =
                    sourceAnalyzer
                            .findMethodLineNumber(
                                    javaFile,
                                    controllerMethodName
                            );


            /*
             * We found the class but not necessarily
             * the method.
             *
             * Still return useful source information.
             */
            return Optional.of(
                    new SecuritySourceLocation(
                            controllerClassName,
                            controllerMethodName,
                            buildRelativePath(
                                    projectDirectory,
                                    javaFile
                            ),
                            lineNumber.orElse(0)
                    )
            );
        }


        return Optional.empty();
    }


    /**
     * Prefer a project-relative path in reports.
     *
     * Instead of:
     *
     * C:/Users/.../temp123/demo/src/main/java/...
     *
     * display:
     *
     * demo/src/main/java/...
     */
    private String buildRelativePath(
            Path projectDirectory,
            Path javaFile) {

        try {

            return projectDirectory
                    .toAbsolutePath()
                    .normalize()
                    .relativize(
                            javaFile
                                    .toAbsolutePath()
                                    .normalize()
                    )
                    .toString();

        } catch (IllegalArgumentException exception) {

            /*
             * Defensive fallback if the paths
             * cannot be relativized.
             */
            return javaFile.toString();
        }
    }
}