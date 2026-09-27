package com.research.securitypolicy.loader;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.research.securitypolicy.policy.ApiPolicy;
import com.research.securitypolicy.policy.PolicyDocument;

public class PolicyLoader {

    private final ObjectMapper yamlMapper;

    public PolicyLoader() {

        this.yamlMapper =
                new ObjectMapper(
                        new YAMLFactory()
                );
    }

    public List<ApiPolicy> load(
            InputStream inputStream) {

        if (inputStream == null) {

            throw new IllegalArgumentException(
                    "Security policy input stream must not be null"
            );
        }

        try {

            PolicyDocument document =
                    yamlMapper.readValue(
                            inputStream,
                            PolicyDocument.class
                    );

            if (document == null
                    || document.getPolicies() == null) {

                return List.of();
            }

            return document.getPolicies();

        } catch (IOException exception) {

            throw new IllegalStateException(
                    "Unable to load security policy YAML",
                    exception
            );
        }
    }
}