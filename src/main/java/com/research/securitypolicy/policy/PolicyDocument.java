package com.research.securitypolicy.policy;

import java.util.ArrayList;
import java.util.List;

public class PolicyDocument {

    private List<ApiPolicy> policies =
            new ArrayList<>();

    public List<ApiPolicy> getPolicies() {
        return policies;
    }

    public void setPolicies(
            List<ApiPolicy> policies) {

        this.policies =
                policies == null
                        ? new ArrayList<>()
                        : policies;
    }
}