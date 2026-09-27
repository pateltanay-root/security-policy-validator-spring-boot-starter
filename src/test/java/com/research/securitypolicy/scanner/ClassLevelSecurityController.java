package com.research.securitypolicy.scanner;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/class-test")
@PreAuthorize("hasRole('USER')")
public class ClassLevelSecurityController {

    @GetMapping("/default")
    public String defaultEndpoint() {
        return "default";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint() {
        return "admin";
    }
}