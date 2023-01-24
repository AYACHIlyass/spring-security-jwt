package com.example.springsecurityjwt.db.entity;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "_user")
public class User {
    @Id
    @GeneratedValue
    private long id;
    private String email;
    private String password;
    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    // create a join table.
    @CollectionTable
    // how to store enum.
    @Enumerated(EnumType.STRING)
    private List<Role> roles;


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

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

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", roles=" + roles +
                '}';
    }
}
