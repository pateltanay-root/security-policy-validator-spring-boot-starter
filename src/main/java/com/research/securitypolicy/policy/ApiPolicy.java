package com.research.securitypolicy.policy;

import java.util.ArrayList;
import java.util.List;

public class ApiPolicy {

    private String method;

    private String endpoint;

    private String access = "ROLE_BASED";

    private List<String> roles = new ArrayList<>();

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getAccess() {
        return access;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getPolicyKey() {

        String normalizedMethod =
                method == null
                        ? ""
                        : method.trim().toUpperCase();

        String normalizedEndpoint =
                endpoint == null
                        ? ""
                        : endpoint.trim();

        return normalizedMethod + ":" + normalizedEndpoint;
    }
}