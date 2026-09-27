package com.research.securitypolicy.reporter;

import com.research.securitypolicy.validator.ValidationResult;

public class ConsoleViolationReporter
        implements ViolationReporter {

    @Override
    public void report(
            ValidationResult result) {

    	System.out.println("\n========================================");
    	System.out.println(" SECURITY POLICY VIOLATION");
    	System.out.println("========================================");

        System.out.println(
                "Endpoint : "
                        + result.getEndpoint()
        );

        System.out.println(
                "Type     : "
                        + result.getViolationType()
        );

        System.out.println(
                "Severity : "
                        + result.getSeverity()
        );

        System.out.println(
                "Expected : "
                        + result.getExpected()
        );

        System.out.println(
                "Actual   : "
                        + result.getActual()
        );

        System.out.println(
                "Message  : "
                        + result.getMessage()
        );
    }
}
