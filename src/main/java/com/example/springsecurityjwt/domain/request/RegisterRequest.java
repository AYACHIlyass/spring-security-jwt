package com.example.springsecurityjwt.domain.request;

import com.example.springsecurityjwt.db.entity.Role;

import java.util.List;

public class RegisterRequest {

    private String email;
    private String password;

    private List<Role> roles;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }
}
