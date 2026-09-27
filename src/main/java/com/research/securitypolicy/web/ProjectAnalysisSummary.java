package com.research.securitypolicy.web;

public class ProjectAnalysisSummary {

    private final int javaFiles;
    private final int controllers;
    private final int policies;
    private final int endpoints;

    public ProjectAnalysisSummary(
            int javaFiles,
            int controllers,
            int policies,
            int endpoints) {

        this.javaFiles = javaFiles;
        this.controllers = controllers;
        this.policies = policies;
        this.endpoints = endpoints;
    }

    public int getJavaFiles() {
        return javaFiles;
    }

    public int getControllers() {
        return controllers;
    }

    public int getPolicies() {
        return policies;
    }

    public int getEndpoints() {
        return endpoints;
    }
}