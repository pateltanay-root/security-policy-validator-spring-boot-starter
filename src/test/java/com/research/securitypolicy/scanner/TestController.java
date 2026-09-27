package com.research.securitypolicy.scanner;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.annotation.Secured;

import jakarta.annotation.security.RolesAllowed;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "public";
    }
    
    @GetMapping("/secured")
    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
    public String securedEndpoint() {
        return "secured";
    }

    @GetMapping("/roles-allowed")
    @RolesAllowed({"ADMIN", "AUDITOR"})
    public String rolesAllowedEndpoint() {
        return "roles allowed";
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','MANAGER')")
    public String update() {
        return "updated";
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String delete() {
        return "deleted";
    }
}