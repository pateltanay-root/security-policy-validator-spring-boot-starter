package com.research.securitypolicy.source;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;

import com.research.securitypolicy.model.EndpointDefinition;

public class StaticEndpointExtractor {

    public List<EndpointDefinition> extract(
            List<Path> controllerFiles)
            throws IOException {

        List<EndpointDefinition> endpoints =
                new ArrayList<>();

        if (controllerFiles == null
                || controllerFiles.isEmpty()) {

            return endpoints;
        }

        for (Path controllerFile : controllerFiles) {

            endpoints.addAll(
                    extract(controllerFile)
            );
        }

        return endpoints;
    }


    public List<EndpointDefinition> extract(
            Path controllerFile)
            throws IOException {

        if (controllerFile == null) {
            throw new IllegalArgumentException(
                    "Controller file must not be null"
            );
        }

        CompilationUnit unit =
                StaticJavaParser.parse(
                        controllerFile
                );

        List<EndpointDefinition> endpoints =
                new ArrayList<>();


        for (ClassOrInterfaceDeclaration controller :
                unit.findAll(
                        ClassOrInterfaceDeclaration.class
                )) {

            if (!isController(controller)) {
                continue;
            }

            String classPath =
                    extractClassPath(controller);


            for (MethodDeclaration method :
                    controller.getMethods()) {

                MappingInformation mapping =
                        extractMapping(method);

                if (mapping == null) {
                    continue;
                }


                String completePath =
                        combinePaths(
                                classPath,
                                mapping.path()
                        );


                SecurityInformation security =
                        extractSecurity(method);


                EndpointDefinition endpoint =
                        new EndpointDefinition();

                endpoint.setHttpMethod(
                        mapping.httpMethod()
                );

                endpoint.setPath(
                        completePath
                );

                endpoint.setAuthorizationExpression(
                        security.expression()
                );

                endpoint.setRoles(
                        security.roles()
                );


                endpoints.add(endpoint);
            }
        }

        return endpoints;
    }


    private boolean isController(
            ClassOrInterfaceDeclaration declaration) {

        return declaration
                .getAnnotationByName(
                        "RestController"
                )
                .isPresent()
                ||
                declaration
                        .getAnnotationByName(
                                "Controller"
                        )
                        .isPresent();
    }


    /*
     * Extract class-level:
     *
     * @RequestMapping("/api/patients")
     */
    private String extractClassPath(
            ClassOrInterfaceDeclaration controller) {

        return controller
                .getAnnotationByName(
                        "RequestMapping"
                )
                .map(this::extractAnnotationPath)
                .orElse("");
    }


    /*
     * Extract mappings such as:
     *
     * @GetMapping
     * @PostMapping
     * @PutMapping
     * @DeleteMapping
     * @PatchMapping
     *
     * and:
     *
     * @RequestMapping(
     *     value="/test",
     *     method=RequestMethod.GET
     * )
     */
    private MappingInformation extractMapping(
            MethodDeclaration method) {

        for (AnnotationExpr annotation :
                method.getAnnotations()) {

            String name =
                    annotation.getNameAsString();


            switch (name) {

                case "GetMapping":

                    return new MappingInformation(
                            "GET",
                            extractAnnotationPath(
                                    annotation
                            )
                    );


                case "PostMapping":

                    return new MappingInformation(
                            "POST",
                            extractAnnotationPath(
                                    annotation
                            )
                    );


                case "PutMapping":

                    return new MappingInformation(
                            "PUT",
                            extractAnnotationPath(
                                    annotation
                            )
                    );


                case "DeleteMapping":

                    return new MappingInformation(
                            "DELETE",
                            extractAnnotationPath(
                                    annotation
                            )
                    );


                case "PatchMapping":

                    return new MappingInformation(
                            "PATCH",
                            extractAnnotationPath(
                                    annotation
                            )
                    );


                case "RequestMapping":

                    String httpMethod =
                            extractRequestMappingMethod(
                                    annotation
                            );

                    if (httpMethod == null) {
                        continue;
                    }

                    return new MappingInformation(
                            httpMethod,
                            extractAnnotationPath(
                                    annotation
                            )
                    );


                default:
                    break;
            }
        }

        return null;
    }


    private String extractRequestMappingMethod(
            AnnotationExpr annotation) {

        if (!(annotation
                instanceof NormalAnnotationExpr normal)) {

            return null;
        }


        for (MemberValuePair pair :
                normal.getPairs()) {

            if (!pair
                    .getNameAsString()
                    .equals("method")) {

                continue;
            }


            String value =
                    pair.getValue()
                            .toString();


            int dot =
                    value.lastIndexOf('.');

            if (dot >= 0) {
                value =
                        value.substring(
                                dot + 1
                        );
            }


            value =
                    value.replaceAll(
                            "[^A-Za-z]",
                            ""
                    );


            if (!value.isBlank()) {

                return value.toUpperCase(
                        Locale.ROOT
                );
            }
        }

        return null;
    }


    /*
     * Supports:
     *
     * @GetMapping("/patients")
     *
     * @GetMapping(value="/patients")
     *
     * @GetMapping(path="/patients")
     */
    private String extractAnnotationPath(
            AnnotationExpr annotation) {

        if (annotation
                instanceof SingleMemberAnnotationExpr single) {

            return extractStringValue(
                    single.getMemberValue()
            );
        }


        if (annotation
                instanceof NormalAnnotationExpr normal) {

            for (MemberValuePair pair :
                    normal.getPairs()) {

                String name =
                        pair.getNameAsString();

                if (name.equals("value")
                        || name.equals("path")) {

                    return extractStringValue(
                            pair.getValue()
                    );
                }
            }
        }


        return "";
    }


    private String extractStringValue(
            Expression expression) {

        if (expression.isStringLiteralExpr()) {

            return expression
                    .asStringLiteralExpr()
                    .asString();
        }


        if (expression
                instanceof ArrayInitializerExpr array) {

            NodeList<Expression> values =
                    array.getValues();

            if (!values.isEmpty()
                    &&
                    values.get(0)
                            .isStringLiteralExpr()) {

                return values
                        .get(0)
                        .asStringLiteralExpr()
                        .asString();
            }
        }


        return "";
    }


    /*
     * Extract:
     *
     * @PreAuthorize("hasRole('ADMIN')")
     *
     * @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
     *
     * @RolesAllowed({"ADMIN", "AUDITOR"})
     */
    private SecurityInformation extractSecurity(
            MethodDeclaration method) {

        for (AnnotationExpr annotation :
                method.getAnnotations()) {

            String name =
                    annotation.getNameAsString();


            if (name.equals(
                    "PreAuthorize"
            )) {

                String expression =
                        extractSecurityExpression(
                                annotation
                        );

                return new SecurityInformation(
                        expression,
                        extractRolesFromExpression(
                                expression
                        )
                );
            }


            if (name.equals(
                    "Secured"
            )) {

                List<String> roles =
                        extractRolesFromAnnotation(
                                annotation
                        );

                return new SecurityInformation(
                        "SECURED:"
                                + String.join(
                                        ",",
                                        roles
                                ),
                        roles
                );
            }


            if (name.equals(
                    "RolesAllowed"
            )) {

                List<String> roles =
                        extractRolesFromAnnotation(
                                annotation
                        );

                return new SecurityInformation(
                        "ROLES_ALLOWED:"
                                + String.join(
                                        ",",
                                        roles
                                ),
                        roles
                );
            }
        }


        /*
         * No authorization annotation.
         */
        return new SecurityInformation(
                null,
                List.of()
        );
    }


    private String extractSecurityExpression(
            AnnotationExpr annotation) {

        if (annotation
                instanceof SingleMemberAnnotationExpr single
                &&
                single.getMemberValue()
                        .isStringLiteralExpr()) {

            return single
                    .getMemberValue()
                    .asStringLiteralExpr()
                    .asString();
        }

        return null;
    }


    private List<String> extractRolesFromExpression(
            String expression) {

        List<String> roles =
                new ArrayList<>();

        if (expression == null
                || expression.isBlank()) {

            return roles;
        }


        /*
         * Extract quoted values from expressions like:
         *
         * hasRole('ADMIN')
         *
         * hasAnyRole('ADMIN','MANAGER')
         */
        java.util.regex.Matcher matcher =
                java.util.regex.Pattern
                        .compile(
                                "['\"]([^'\"]+)['\"]"
                        )
                        .matcher(
                                expression
                        );


        while (matcher.find()) {

            String role =
                    normalizeRole(
                            matcher.group(1)
                    );

            if (!role.isBlank()
                    && !roles.contains(role)) {

                roles.add(role);
            }
        }


        return roles;
    }


    private List<String> extractRolesFromAnnotation(
            AnnotationExpr annotation) {

        List<String> roles =
                new ArrayList<>();


        if (annotation
                instanceof SingleMemberAnnotationExpr single) {

            collectRoles(
                    single.getMemberValue(),
                    roles
            );
        }


        if (annotation
                instanceof NormalAnnotationExpr normal) {

            for (MemberValuePair pair :
                    normal.getPairs()) {

                if (pair.getNameAsString()
                        .equals("value")) {

                    collectRoles(
                            pair.getValue(),
                            roles
                    );
                }
            }
        }


        return roles;
    }


    private void collectRoles(
            Expression expression,
            List<String> roles) {

        if (expression.isStringLiteralExpr()) {

            roles.add(
                    normalizeRole(
                            expression
                                    .asStringLiteralExpr()
                                    .asString()
                    )
            );

            return;
        }


        if (expression
                instanceof ArrayInitializerExpr array) {

            for (Expression value :
                    array.getValues()) {

                if (value.isStringLiteralExpr()) {

                    roles.add(
                            normalizeRole(
                                    value
                                            .asStringLiteralExpr()
                                            .asString()
                            )
                    );
                }
            }
        }
    }


    private String normalizeRole(
            String role) {

        if (role == null) {
            return "";
        }


        String normalized =
                role.trim();


        if (normalized.startsWith(
                "ROLE_"
        )) {

            normalized =
                    normalized.substring(
                            "ROLE_".length()
                    );
        }


        return normalized
                .toUpperCase(
                        Locale.ROOT
                );
    }


    private String combinePaths(
            String classPath,
            String methodPath) {

        String first =
                normalizePath(
                        classPath
                );

        String second =
                normalizePath(
                        methodPath
                );


        if (first.equals("/")) {
            return second;
        }


        if (second.equals("/")) {
            return first;
        }


        return first
                + second;
    }


    private String normalizePath(
            String path) {

        if (path == null
                || path.isBlank()) {

            return "/";
        }


        String normalized =
                path.trim();


        if (!normalized.startsWith("/")) {
            normalized =
                    "/" + normalized;
        }


        while (normalized.length() > 1
                &&
                normalized.endsWith("/")) {

            normalized =
                    normalized.substring(
                            0,
                            normalized.length() - 1
                    );
        }


        return normalized;
    }


    private record MappingInformation(
            String httpMethod,
            String path) {
    }


    private record SecurityInformation(
            String expression,
            List<String> roles) {
    }
}