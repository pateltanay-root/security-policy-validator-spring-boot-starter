package com.research.securitypolicy.source;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.validator.ValidationResult;

/**
 * Adds controller source-code locations to
 * validation results.
 */
public class ValidationResultSourceEnricher {

    private final SecuritySourceLocator sourceLocator;


    public ValidationResultSourceEnricher() {

        this.sourceLocator =
                new SecuritySourceLocator();
    }


    public ValidationResultSourceEnricher(
            SecuritySourceLocator sourceLocator) {

        if (sourceLocator == null) {
            throw new IllegalArgumentException(
                    "SecuritySourceLocator must not be null"
            );
        }

        this.sourceLocator = sourceLocator;
    }


    public void enrich(
            Path projectDirectory,
            List<EndpointDefinition> endpoints,
            List<ValidationResult> results)
            throws IOException {

        if (projectDirectory == null) {
            throw new IllegalArgumentException(
                    "Project directory must not be null"
            );
        }

        if (endpoints == null
                || endpoints.isEmpty()
                || results == null
                || results.isEmpty()) {

            return;
        }


        Map<String, EndpointDefinition> endpointMap =
                new HashMap<>();

        for (EndpointDefinition endpoint : endpoints) {

            if (endpoint == null) {
                continue;
            }

            endpointMap.put(
                    endpoint.getEndpointKey(),
                    endpoint
            );
        }


        for (ValidationResult result : results) {

            if (result == null
                    || result.getEndpoint() == null) {

                continue;
            }


            EndpointDefinition endpoint =
                    endpointMap.get(
                            result.getEndpoint()
                    );


            if (endpoint == null) {
                continue;
            }


            sourceLocator
                    .locate(
                            projectDirectory,
                            endpoint
                    )
                    .ifPresent(
                            result::setSourceLocation
                    );
        }
    }
}