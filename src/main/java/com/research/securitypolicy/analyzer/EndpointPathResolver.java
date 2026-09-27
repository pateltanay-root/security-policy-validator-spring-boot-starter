package com.research.securitypolicy.analyzer;

public class EndpointPathResolver {

    public String resolve(String pattern) {

        if (pattern == null || pattern.isBlank()) {
            return "/";
        }

        return pattern.replaceAll(
                "\\{[^{}]+}",
                "1"
        );
    }
}