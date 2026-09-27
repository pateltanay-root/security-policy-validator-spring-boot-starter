package com.research.securitypolicy.validator;

import com.research.securitypolicy.source.SecuritySourceLocation;

public class ValidationResult {

    private String endpoint;

    private ViolationType violationType;

    private Severity severity;

    private String message;

    private String expected;

    private String actual;

    /*
     * Optional source-code location.
     *
     * Used by the website/report to show exactly
     * where the security misconfiguration occurred.
     */
    private SecuritySourceLocation sourceLocation;


    public ValidationResult() {
    }


    /*
     * Existing constructor kept unchanged
     * for backward compatibility.
     */
    public ValidationResult(
            String endpoint,
            ViolationType violationType,
            Severity severity,
            String message,
            String expected,
            String actual) {

        this.endpoint = endpoint;
        this.violationType = violationType;
        this.severity = severity;
        this.message = message;
        this.expected = expected;
        this.actual = actual;
    }


    /*
     * New constructor including source location.
     */
    public ValidationResult(
            String endpoint,
            ViolationType violationType,
            Severity severity,
            String message,
            String expected,
            String actual,
            SecuritySourceLocation sourceLocation) {

        this.endpoint = endpoint;
        this.violationType = violationType;
        this.severity = severity;
        this.message = message;
        this.expected = expected;
        this.actual = actual;
        this.sourceLocation = sourceLocation;
    }


    public String getEndpoint() {
        return endpoint;
    }


    public void setEndpoint(
            String endpoint) {

        this.endpoint = endpoint;
    }


    public ViolationType getViolationType() {
        return violationType;
    }


    public void setViolationType(
            ViolationType violationType) {

        this.violationType = violationType;
    }


    public Severity getSeverity() {
        return severity;
    }


    public void setSeverity(
            Severity severity) {

        this.severity = severity;
    }


    public String getMessage() {
        return message;
    }


    public void setMessage(
            String message) {

        this.message = message;
    }


    public String getExpected() {
        return expected;
    }


    public void setExpected(
            String expected) {

        this.expected = expected;
    }


    public String getActual() {
        return actual;
    }


    public void setActual(
            String actual) {

        this.actual = actual;
    }


    public SecuritySourceLocation getSourceLocation() {
        return sourceLocation;
    }


    public void setSourceLocation(
            SecuritySourceLocation sourceLocation) {

        this.sourceLocation = sourceLocation;
    }
}