package com.research.securitypolicy.model;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class EndpointDefinition {

    /*
     * HTTP information
     */
    private String httpMethod;

    private String path;


    /*
     * Legacy fields.
     *
     * We are keeping these temporarily because
     * the existing validator and tests still use them.
     */
    private String authorizationExpression;

    private List<String> roles =
            new ArrayList<>();


    /*
     * New structured authorization model.
     */
    private AuthorizationDefinition authorization;


    /*
     * Controller metadata.
     *
     * Useful later for reporting exactly where
     * a security issue was found.
     */
    private Method controllerMethod;

    private Class<?> controllerClass;


    public EndpointDefinition() {
    }


    public EndpointDefinition(
            String httpMethod,
            String path,
            String authorizationExpression,
            List<String> roles,
            Method controllerMethod,
            Class<?> controllerClass) {

        this.httpMethod = httpMethod;
        this.path = path;
        this.authorizationExpression =
                authorizationExpression;

        this.roles =
                roles == null
                        ? new ArrayList<>()
                        : new ArrayList<>(roles);

        this.controllerMethod =
                controllerMethod;

        this.controllerClass =
                controllerClass;
    }


    /*
     * Optional constructor using the
     * new structured authorization model.
     */
    public EndpointDefinition(
            String httpMethod,
            String path,
            AuthorizationDefinition authorization,
            Method controllerMethod,
            Class<?> controllerClass) {

        this.httpMethod = httpMethod;
        this.path = path;
        this.authorization = authorization;
        this.controllerMethod = controllerMethod;
        this.controllerClass = controllerClass;

        /*
         * Keep legacy fields synchronized.
         */
        if (authorization != null) {

            this.authorizationExpression =
                    authorization.getRawExpression();

            this.roles =
                    authorization.getRoles() == null
                            ? new ArrayList<>()
                            : new ArrayList<>(
                                    authorization.getRoles()
                            );
        }
    }


    public String getHttpMethod() {
        return httpMethod;
    }


    public void setHttpMethod(
            String httpMethod) {

        this.httpMethod = httpMethod;
    }


    public String getPath() {
        return path;
    }


    public void setPath(
            String path) {

        this.path = path;
    }


    public String getAuthorizationExpression() {
        return authorizationExpression;
    }


    public void setAuthorizationExpression(
            String authorizationExpression) {

        this.authorizationExpression =
                authorizationExpression;
    }


    public List<String> getRoles() {
        return roles;
    }


    public void setRoles(
            List<String> roles) {

        this.roles =
                roles == null
                        ? new ArrayList<>()
                        : new ArrayList<>(roles);
    }


    public AuthorizationDefinition getAuthorization() {
        return authorization;
    }


    public void setAuthorization(
            AuthorizationDefinition authorization) {

        this.authorization = authorization;
    }


    public Method getControllerMethod() {
        return controllerMethod;
    }


    public void setControllerMethod(
            Method controllerMethod) {

        this.controllerMethod =
                controllerMethod;
    }


    public Class<?> getControllerClass() {
        return controllerClass;
    }


    public void setControllerClass(
            Class<?> controllerClass) {

        this.controllerClass =
                controllerClass;
    }


    /*
     * Unique endpoint identifier used by
     * the validator to match an API with
     * its YAML policy.
     *
     * Example:
     *
     * PUT:/api/patients/{id}
     */
    public String getEndpointKey() {

        String method =
                httpMethod == null
                        ? ""
                        : httpMethod
                                .trim()
                                .toUpperCase();

        String endpointPath =
                path == null
                        ? ""
                        : path.trim();

        return method
                + ":"
                + endpointPath;
    }


    /*
     * Helpful later for reports.
     *
     * Example:
     *
     * PatientController.updatePatient
     */
    public String getControllerLocation() {

        if (controllerClass == null) {
            return "Unknown controller";
        }

        if (controllerMethod == null) {
            return controllerClass.getSimpleName();
        }

        return controllerClass.getSimpleName()
                + "."
                + controllerMethod.getName();
    }


    @Override
    public String toString() {

        return "EndpointDefinition{"
                + "httpMethod='"
                + httpMethod
                + '\''
                + ", path='"
                + path
                + '\''
                + ", authorizationExpression='"
                + authorizationExpression
                + '\''
                + ", roles="
                + roles
                + ", authorization="
                + authorization
                + ", controller="
                + getControllerLocation()
                + '}';
    }
}