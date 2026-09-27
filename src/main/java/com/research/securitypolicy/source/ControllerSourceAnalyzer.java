package com.research.securitypolicy.source;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;

public class ControllerSourceAnalyzer {

    public boolean isController(
            Path javaFile)
            throws IOException {

        CompilationUnit unit =
                parse(javaFile);

        return findControllerClass(unit)
                .isPresent();
    }


    public Optional<ClassOrInterfaceDeclaration>
            findControllerClass(
                    Path javaFile)
                    throws IOException {

        return findControllerClass(
                parse(javaFile)
        );
    }


    public List<MethodDeclaration>
            findControllerMethods(
                    Path javaFile)
                    throws IOException {

        Optional<ClassOrInterfaceDeclaration> controller =
                findControllerClass(
                        javaFile
                );

        if (controller.isEmpty()) {
            return List.of();
        }

        return new ArrayList<>(
                controller
                        .get()
                        .getMethods()
        );
    }


    public Optional<MethodDeclaration>
            findMethod(
                    Path javaFile,
                    String methodName)
                    throws IOException {

        if (methodName == null
                || methodName.isBlank()) {
            return Optional.empty();
        }

        return findControllerMethods(
                javaFile
        )
        .stream()
        .filter(method ->
                method.getNameAsString()
                        .equals(methodName)
        )
        .findFirst();
    }


    public Optional<Integer>
            findMethodLineNumber(
                    Path javaFile,
                    String methodName)
                    throws IOException {

        Optional<MethodDeclaration> method =
                findMethod(
                        javaFile,
                        methodName
                );

        if (method.isEmpty()) {
            return Optional.empty();
        }

        return method
                .get()
                .getBegin()
                .map(position ->
                        position.line
                );
    }


    public Optional<String>
            findControllerClassName(
                    Path javaFile)
                    throws IOException {

        return findControllerClass(
                javaFile
        )
        .map(
                ClassOrInterfaceDeclaration
                        ::getNameAsString
        );
    }


    private CompilationUnit parse(
            Path javaFile)
            throws IOException {

        if (javaFile == null) {
            throw new IllegalArgumentException(
                    "Java file must not be null"
            );
        }

        if (!Files.exists(javaFile)) {
            throw new IllegalArgumentException(
                    "Java file does not exist: "
                            + javaFile
            );
        }

        if (!Files.isRegularFile(javaFile)) {
            throw new IllegalArgumentException(
                    "Path is not a regular file: "
                            + javaFile
            );
        }

        return StaticJavaParser.parse(
                javaFile
        );
    }


    private Optional<ClassOrInterfaceDeclaration>
            findControllerClass(
                    CompilationUnit unit) {

        return unit
                .findAll(
                        ClassOrInterfaceDeclaration.class
                )
                .stream()
                .filter(clazz ->
                        clazz.getAnnotationByName(
                                "RestController"
                        ).isPresent()
                        ||
                        clazz.getAnnotationByName(
                                "Controller"
                        ).isPresent()
                )
                .findFirst();
    }
}