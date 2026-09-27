package com.research.securitypolicy.web;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.research.securitypolicy.model.EndpointDefinition;
import com.research.securitypolicy.source.StaticEndpointExtractor;
import com.research.securitypolicy.loader.PolicyLoader;
import com.research.securitypolicy.policy.ApiPolicy;
import com.research.securitypolicy.source.ControllerSourceScanner;
import com.research.securitypolicy.source.JavaProjectScanner;
import com.research.securitypolicy.source.ValidationResultSourceEnricher;
import com.research.securitypolicy.upload.ProjectExtractor;
import com.research.securitypolicy.validator.SecurityPolicyValidator;
import com.research.securitypolicy.validator.ValidationResult;

@Service
public class ProjectAnalysisService {

    private final ProjectExtractor projectExtractor;

    private final JavaProjectScanner javaProjectScanner;

    private final ControllerSourceScanner controllerSourceScanner;
    
    private final StaticEndpointExtractor staticEndpointExtractor;

    public ProjectAnalysisService() {

        this.projectExtractor =
                new ProjectExtractor();
        
        this.staticEndpointExtractor =
                new StaticEndpointExtractor();

        this.javaProjectScanner =
                new JavaProjectScanner();

        this.controllerSourceScanner =
                new ControllerSourceScanner();
    }


    public ProjectAnalysisReport analyze(
            MultipartFile projectZip,
            MultipartFile policyFile)
            throws IOException {

        validateUploads(
                projectZip,
                policyFile
        );


        /*
         * 1. Extract uploaded Spring Boot ZIP.
         */
        Path projectDirectory =
                projectExtractor.extract(
                        projectZip.getInputStream()
                );


        /*
         * 2. Discover all Java source files.
         */
        List<Path> javaFiles =
                javaProjectScanner.findJavaFiles(
                        projectDirectory
                );


        /*
         * 3. Discover Spring MVC controller files.
         */
        List<Path> controllerFiles =
                controllerSourceScanner
                        .findControllerFiles(
                                javaFiles
                        );
        
        /*
         * 4. Extract endpoint definitions from controllers.
         */
        List<EndpointDefinition> endpoints =
                staticEndpointExtractor.extract(
                        controllerFiles
                );


        /*
         * 4. Load expected policies from YAML.
         */
        PolicyLoader policyLoader =
                new PolicyLoader();


        List<ApiPolicy> policies =
                policyLoader.load(
                        policyFile.getInputStream()
                );


        /*
         * 5. Current summary.
         *
         * Later we can extend this with endpoint and
         * violation counts.
         */
        ProjectAnalysisSummary summary =
        		new ProjectAnalysisSummary(
        		        javaFiles.size(),
        		        controllerFiles.size(),
        		        policies.size(),
        		        endpoints.size()
        		);
        
        /*
         * 6. Violations are temporarily empty.
         *
         * The next step will connect static endpoint
         * extraction + SecurityPolicyValidator here.
         */
        SecurityPolicyValidator validator =
                new SecurityPolicyValidator();

        List<ValidationResult> violations =
                validator.validate(
                        endpoints,
                        policies
                );
        
        ValidationResultSourceEnricher enricher =
                new ValidationResultSourceEnricher();

        enricher.enrich(
                projectDirectory,
                endpoints,
                violations
        );
        
        /*
         * 7. Build final API response.
         */
        return new ProjectAnalysisReport(
                summary,
                violations
        );
    }


    private void validateUploads(
            MultipartFile projectZip,
            MultipartFile policyFile) {

        if (projectZip == null
                || projectZip.isEmpty()) {

            throw new IllegalArgumentException(
                    "Project ZIP is required"
            );
        }


        if (policyFile == null
                || policyFile.isEmpty()) {

            throw new IllegalArgumentException(
                    "Policy YAML is required"
            );
        }
    }
}