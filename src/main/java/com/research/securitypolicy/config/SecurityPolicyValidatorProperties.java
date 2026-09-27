package com.research.securitypolicy.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(
        prefix = "security-policy-validator"
)
public class SecurityPolicyValidatorProperties {

    private boolean enabled = true;

    private String policyLocation =
            "classpath:security-policy.yml";

    private List<String> failOn =
            new ArrayList<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getPolicyLocation() {
        return policyLocation;
    }

    public void setPolicyLocation(
            String policyLocation) {

        this.policyLocation = policyLocation;
    }

    public List<String> getFailOn() {
        return failOn;
    }

    public void setFailOn(
            List<String> failOn) {

        this.failOn = failOn;
    }
}