package com.research.securitypolicy.source;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class JavaProjectScanner {

    public List<Path> findJavaFiles(
            Path projectDirectory)
            throws IOException {

        if (projectDirectory == null) {
            throw new IllegalArgumentException(
                    "Project directory must not be null"
            );
        }

        if (!Files.exists(projectDirectory)) {
            throw new IllegalArgumentException(
                    "Project directory does not exist"
            );
        }

        try (var paths = Files.walk(projectDirectory)) {

            return paths
                    .filter(Files::isRegularFile)
                    .filter(path ->
                            path.getFileName()
                                    .toString()
                                    .endsWith(".java")
                    )
                    .toList();
        }
    }
}