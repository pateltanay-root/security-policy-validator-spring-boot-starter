package com.research.securitypolicy.web;

import java.util.ArrayList;
import java.util.List;

import com.research.securitypolicy.validator.ValidationResult;

public class ProjectAnalysisReport {

    private ProjectAnalysisSummary summary;

    private List<ValidationResult> violations =
            new ArrayList<>();


    public ProjectAnalysisReport() {
    }


    public ProjectAnalysisReport(
            ProjectAnalysisSummary summary,
            List<ValidationResult> violations) {

        this.summary = summary;

        this.violations =
                violations == null
                        ? new ArrayList<>()
                        : new ArrayList<>(violations);
    }


    public ProjectAnalysisSummary getSummary() {
        return summary;
    }


    public void setSummary(
            ProjectAnalysisSummary summary) {

        this.summary = summary;
    }


    public List<ValidationResult> getViolations() {
        return violations;
    }


    public void setViolations(
            List<ValidationResult> violations) {

        this.violations =
                violations == null
                        ? new ArrayList<>()
                        : new ArrayList<>(violations);
    }
}