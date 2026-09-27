package com.research.securitypolicy.reporter;

import com.research.securitypolicy.validator.ValidationResult;

public interface ViolationReporter {

    void report(ValidationResult result);
}