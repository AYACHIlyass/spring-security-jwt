package com.example.springsecurityjwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/")
public class DemoController {

    @GetMapping("greetUser/")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String greetUser(Principal principal) {
        return String.format("hello user %s", principal.getName());
    }
    @GetMapping("greetAdmin/")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String greetAdmin(Principal principal) {
        return String.format("hello admin %s", principal.getName());
    }
}
