package com.research.securitypolicy.web;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/analysis")
public class AnalysisUploadController {

    private final ProjectAnalysisService analysisService;


    public AnalysisUploadController(
            ProjectAnalysisService analysisService) {

        if (analysisService == null) {
            throw new IllegalArgumentException(
                    "ProjectAnalysisService must not be null"
            );
        }

        this.analysisService =
                analysisService;
    }


    @PostMapping
    public ResponseEntity<?> analyze(
            @RequestParam("project")
            MultipartFile projectZip,

            @RequestParam("policy")
            MultipartFile policyFile) {

        /*
         * Validate project upload.
         */
        if (projectZip == null
                || projectZip.isEmpty()) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    "Spring Boot project ZIP is required"
                            )
                    );
        }


        /*
         * Validate policy upload.
         */
        if (policyFile == null
                || policyFile.isEmpty()) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    "Security policy YAML file is required"
                            )
                    );
        }


        /*
         * Validate project extension.
         */
        String projectFileName =
                projectZip.getOriginalFilename();


        if (projectFileName == null
                ||
                !projectFileName
                        .toLowerCase()
                        .endsWith(".zip")) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    "Project file must be a .zip file"
                            )
                    );
        }


        /*
         * Validate YAML extension.
         */
        String policyFileName =
                policyFile.getOriginalFilename();


        if (policyFileName == null
                ||
                !(
                        policyFileName
                                .toLowerCase()
                                .endsWith(".yml")
                        ||
                        policyFileName
                                .toLowerCase()
                                .endsWith(".yaml")
                )) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    "Policy file must be a .yml or .yaml file"
                            )
                    );
        }


        try {

            ProjectAnalysisReport report =
                    analysisService.analyze(
                            projectZip,
                            policyFile
                    );


            return ResponseEntity.ok(
                    report
            );

        } catch (IllegalArgumentException exception) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "error",
                                    safeMessage(exception)
                            )
                    );

        } catch (IOException exception) {

            return ResponseEntity
                    .internalServerError()
                    .body(
                            Map.of(
                                    "error",
                                    "Failed to read or extract uploaded files"
                            )
                    );

        } catch (Exception exception) {

            return ResponseEntity
                    .internalServerError()
                    .body(
                            Map.of(
                                    "error",
                                    "Analysis failed"
                            )
                    );
        }
    }


    private String safeMessage(
            Exception exception) {

        String message =
                exception.getMessage();


        if (message == null
                || message.isBlank()) {

            return "Invalid analysis request";
        }


        return message;
    }
}