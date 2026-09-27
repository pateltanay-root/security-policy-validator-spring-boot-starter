package com.research.securitypolicy.model;

import java.util.ArrayList;
import java.util.List;

public class AuthorizationDefinition {

    private AccessType accessType;

    private SecuritySource securitySource;

    private List<String> roles =
            new ArrayList<>();

    private String rawExpression;

    public AuthorizationDefinition() {
    }

    public AuthorizationDefinition(
            AccessType accessType,
            SecuritySource securitySource,
            List<String> roles,
            String rawExpression) {

        this.accessType = accessType;

        this.securitySource = securitySource;

        this.roles =
                roles == null
                        ? new ArrayList<>()
                        : new ArrayList<>(roles);

        this.rawExpression = rawExpression;
    }

    public AccessType getAccessType() {
        return accessType;
    }

    public void setAccessType(
            AccessType accessType) {

        this.accessType = accessType;
    }

    public SecuritySource getSecuritySource() {
        return securitySource;
    }

    public void setSecuritySource(
            SecuritySource securitySource) {

        this.securitySource = securitySource;
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

    public String getRawExpression() {
        return rawExpression;
    }

    public void setRawExpression(
            String rawExpression) {

        this.rawExpression = rawExpression;
    }
}