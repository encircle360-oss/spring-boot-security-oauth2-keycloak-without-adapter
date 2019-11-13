package com.encircle360.examples.oauth2resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestAuthController {

    @GetMapping("/principal")
    @PreAuthorize("hasAuthority('SCOPE_PRINCIPAL')")
    public String getPrincipal(JwtAuthenticationToken principal) {
        return principal.toString();
    }

    @GetMapping("/authentication")
    @PreAuthorize("hasAuthority('SCOPE_AUTHENTICATION')")
    public String getAuthentication(Authentication authentication) {
        return authentication.toString();
    }
}
