package com.research.securitypolicy.model;

import java.util.ArrayList;
import java.util.List;

public class RequestSecurityRule {

    private String pattern;

    private String httpMethod;

    private AccessType accessType;

    private List<String> roles = new ArrayList<>();

    private String rawRule;

    public RequestSecurityRule() {
    }

    public RequestSecurityRule(
            String pattern,
            String httpMethod,
            AccessType accessType,
            List<String> roles,
            String rawRule) {

        this.pattern = pattern;
        this.httpMethod = httpMethod;
        this.accessType = accessType;

        this.roles = roles == null
                ? new ArrayList<>()
                : new ArrayList<>(roles);

        this.rawRule = rawRule;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public AccessType getAccessType() {
        return accessType;
    }

    public void setAccessType(
            AccessType accessType) {
        this.accessType = accessType;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {

        this.roles = roles == null
                ? new ArrayList<>()
                : new ArrayList<>(roles);
    }

    public String getRawRule() {
        return rawRule;
    }

    public void setRawRule(String rawRule) {
        this.rawRule = rawRule;
    }
}