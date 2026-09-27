package com.research.securitypolicy.source;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ControllerSourceScanner {

    public List<Path> findControllerFiles(
            List<Path> javaFiles)
            throws IOException {

        List<Path> controllers =
                new ArrayList<>();

        if (javaFiles == null) {
            return controllers;
        }

        for (Path javaFile : javaFiles) {

            if (javaFile == null
                    || !Files.isRegularFile(javaFile)) {
                continue;
            }

            String source =
                    Files.readString(javaFile);

            if (isController(source)) {
                controllers.add(javaFile);
            }
        }

        return controllers;
    }


    private boolean isController(
            String source) {

        if (source == null
                || source.isBlank()) {
            return false;
        }

        return source.contains(
                "@RestController"
        )
        ||
        source.contains(
                "@Controller"
        );
    }
}