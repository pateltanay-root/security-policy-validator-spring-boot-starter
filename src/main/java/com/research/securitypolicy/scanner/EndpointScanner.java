package com.research.securitypolicy.scanner;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.research.securitypolicy.model.AccessType;
import com.research.securitypolicy.model.AuthorizationDefinition;
import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.model.SecuritySource;

import jakarta.annotation.security.RolesAllowed;

public class EndpointScanner {

    private final RequestMappingHandlerMapping handlerMapping;

    public EndpointScanner(
            RequestMappingHandlerMapping handlerMapping) {

        this.handlerMapping = handlerMapping;
    }


    public List<EndpointDefinition> scanEndpoints() {

        List<EndpointDefinition> endpoints =
                new ArrayList<>();

        handlerMapping
                .getHandlerMethods()
                .forEach((mapping, handlerMethod) -> {

                    scanMapping(
                            mapping,
                            handlerMethod,
                            endpoints
                    );
                });

        return endpoints;
    }


    private void scanMapping(
            RequestMappingInfo mapping,
            HandlerMethod handlerMethod,
            List<EndpointDefinition> endpoints) {

        Set<String> paths =
                mapping.getPatternValues();

        Set<RequestMethod> methods =
                mapping
                        .getMethodsCondition()
                        .getMethods();

        /*
         * For the current version, ignore mappings
         * that do not explicitly define an HTTP method.
         */
        if (methods.isEmpty()) {
            return;
        }

        Method controllerMethod =
                handlerMethod.getMethod();

        Class<?> controllerClass =
                handlerMethod.getBeanType();


        /*
         * Extract actual security metadata.
         */
        String authorizationExpression =
                extractAuthorizationExpression(
                        controllerMethod,
                        controllerClass
                );

        List<String> roles =
                extractRoles(
                        authorizationExpression
                );

        AccessType accessType =
                determineAccessType(
                        authorizationExpression,
                        roles
                );

        SecuritySource securitySource =
                determineSecuritySource(
                        authorizationExpression
                );

        AuthorizationDefinition authorization =
                new AuthorizationDefinition(
                        accessType,
                        securitySource,
                        roles,
                        authorizationExpression
                );


        /*
         * One mapping may contain multiple paths
         * and multiple HTTP methods.
         */
        for (String path : paths) {

            for (RequestMethod requestMethod : methods) {

                EndpointDefinition endpoint =
                        new EndpointDefinition();

                endpoint.setHttpMethod(
                        requestMethod.name()
                );

                endpoint.setPath(
                        normalizePath(path)
                );


                /*
                 * Legacy fields retained temporarily
                 * so the existing validator/tests
                 * continue to work.
                 */
                endpoint.setAuthorizationExpression(
                        authorizationExpression
                );

                endpoint.setRoles(
                        new ArrayList<>(roles)
                );


                /*
                 * New structured security model.
                 */
                endpoint.setAuthorization(
                        new AuthorizationDefinition(
                                authorization.getAccessType(),
                                authorization.getSecuritySource(),
                                authorization.getRoles(),
                                authorization.getRawExpression()
                        )
                );


                endpoint.setControllerMethod(
                        controllerMethod
                );

                endpoint.setControllerClass(
                        controllerClass
                );

                endpoints.add(endpoint);
            }
        }
    }


    /**
     * Extracts the effective method-security rule.
     *
     * Method-level security takes precedence over
     * class-level security.
     */
    private String extractAuthorizationExpression(
            Method method,
            Class<?> controllerClass) {

        /*
         * 1. Method-level @PreAuthorize
         */
        PreAuthorize methodPreAuthorize =
                method.getAnnotation(
                        PreAuthorize.class
                );

        if (methodPreAuthorize != null) {

            return methodPreAuthorize.value();
        }


        /*
         * 2. Method-level @Secured
         */
        Secured methodSecured =
                method.getAnnotation(
                        Secured.class
                );

        if (methodSecured != null) {

            return "SECURED:"
                    + String.join(
                            ",",
                            methodSecured.value()
                    );
        }


        /*
         * 3. Method-level @RolesAllowed
         */
        RolesAllowed methodRolesAllowed =
                method.getAnnotation(
                        RolesAllowed.class
                );

        if (methodRolesAllowed != null) {

            return "ROLES_ALLOWED:"
                    + String.join(
                            ",",
                            methodRolesAllowed.value()
                    );
        }


        /*
         * 4. Class-level @PreAuthorize
         */
        PreAuthorize classPreAuthorize =
                controllerClass.getAnnotation(
                        PreAuthorize.class
                );

        if (classPreAuthorize != null) {

            return classPreAuthorize.value();
        }


        /*
         * 5. Class-level @Secured
         */
        Secured classSecured =
                controllerClass.getAnnotation(
                        Secured.class
                );

        if (classSecured != null) {

            return "SECURED:"
                    + String.join(
                            ",",
                            classSecured.value()
                    );
        }


        /*
         * 6. Class-level @RolesAllowed
         */
        RolesAllowed classRolesAllowed =
                controllerClass.getAnnotation(
                        RolesAllowed.class
                );

        if (classRolesAllowed != null) {

            return "ROLES_ALLOWED:"
                    + String.join(
                            ",",
                            classRolesAllowed.value()
                    );
        }


        /*
         * No method-security annotation found.
         */
        return null;
    }


    /**
     * Extracts normalized roles from the security rule.
     */
    private List<String> extractRoles(
            String expression) {

        List<String> roles =
                new ArrayList<>();

        if (expression == null
                || expression.isBlank()) {

            return roles;
        }


        /*
         * @Secured
         *
         * Example:
         * SECURED:ROLE_ADMIN,ROLE_MANAGER
         */
        if (expression.startsWith("SECURED:")) {

            String values =
                    expression.substring(
                            "SECURED:".length()
                    );

            for (String role : values.split(",")) {

                String normalized =
                        normalizeRole(role);

                if (!normalized.isEmpty()) {

                    roles.add(normalized);
                }
            }

            return roles;
        }


        /*
         * @RolesAllowed
         *
         * Example:
         * ROLES_ALLOWED:ADMIN,AUDITOR
         */
        if (expression.startsWith(
                "ROLES_ALLOWED:")) {

            String values =
                    expression.substring(
                            "ROLES_ALLOWED:".length()
                    );

            for (String role : values.split(",")) {

                String normalized =
                        normalizeRole(role);

                if (!normalized.isEmpty()) {

                    roles.add(normalized);
                }
            }

            return roles;
        }


        /*
         * @PreAuthorize
         *
         * Supported in the current version:
         *
         * hasRole('ADMIN')
         *
         * hasAnyRole('ADMIN','MANAGER')
         */
        if (!expression.contains("hasRole")
                && !expression.contains("hasAnyRole")) {

            return roles;
        }

        String cleaned =
                expression
                        .replace("hasAnyRole(", "")
                        .replace("hasRole(", "")
                        .replace(")", "")
                        .replace("'", "")
                        .replace("\"", "");

        for (String role : cleaned.split(",")) {

            String normalized =
                    normalizeRole(role);

            if (!normalized.isEmpty()) {

                roles.add(normalized);
            }
        }

        return roles;
    }


    /**
     * Converts the extracted security rule into the
     * common internal AccessType representation.
     */
    private AccessType determineAccessType(
            String authorizationExpression,
            List<String> roles) {

        /*
         * No method-level or class-level security.
         *
         * At this stage we mark this as PUBLIC from
         * the method-security perspective.
         *
         * Later SecurityFilterChain analysis may
         * replace/augment this result.
         */
        if (authorizationExpression == null
                || authorizationExpression.isBlank()) {

            return AccessType.PUBLIC;
        }


        /*
         * Generic authenticated access.
         */
        String normalizedExpression =
                authorizationExpression
                        .replace(" ", "");

        if (normalizedExpression
                .contains("isAuthenticated()")) {

            return AccessType.AUTHENTICATED;
        }


        /*
         * Role-based access.
         */
        if (roles != null
                && !roles.isEmpty()) {

            return AccessType.ROLE_BASED;
        }


        /*
         * Unknown/custom protected expression.
         *
         * Example:
         *
         * @PreAuthorize(
         *   "@securityService.canAccess(#id)"
         * )
         *
         * We must NOT classify such an expression
         * as PUBLIC.
         */
        return AccessType.AUTHENTICATED;
    }


    /**
     * Identifies where the authorization rule
     * originated.
     */
    private SecuritySource determineSecuritySource(
            String expression) {

        if (expression == null
                || expression.isBlank()) {

            return SecuritySource.NONE;
        }

        if (expression.startsWith("SECURED:")) {

            return SecuritySource.SECURED;
        }

        if (expression.startsWith(
                "ROLES_ALLOWED:")) {

            return SecuritySource.ROLES_ALLOWED;
        }

        return SecuritySource.PRE_AUTHORIZE;
    }


    /**
     * Normalizes role names.
     *
     * ROLE_ADMIN -> ADMIN
     */
    private String normalizeRole(
            String role) {

        if (role == null) {

            return "";
        }

        String normalized =
                role
                        .trim()
                        .replace("\"", "")
                        .replace("'", "");

        if (normalized.startsWith("ROLE_")) {

            normalized =
                    normalized.substring(
                            "ROLE_".length()
                    );
        }

        return normalized;
    }


    /**
     * Normalizes endpoint paths.
     */
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

        normalized =
                normalized.replaceAll(
                        "/{2,}",
                        "/"
                );

        if (normalized.length() > 1
                && normalized.endsWith("/")) {

            normalized =
                    normalized.substring(
                            0,
                            normalized.length() - 1
                    );
        }

        return normalized;
    }
}