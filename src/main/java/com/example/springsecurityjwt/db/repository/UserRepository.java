package com.example.springsecurityjwt.db.repository;

import com.example.springsecurityjwt.db.entity.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findUserByEmail(String email);
}
