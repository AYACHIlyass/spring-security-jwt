package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.configuration.model.UserSecurity;
import com.example.springsecurityjwt.db.entity.User;
import com.example.springsecurityjwt.db.repository.UserRepository;
import com.example.springsecurityjwt.domain.request.AuthenticationRequest;
import com.example.springsecurityjwt.domain.request.RegisterRequest;
import com.example.springsecurityjwt.domain.response.AuthenticationResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder encoder;

    public AuthenticationService(UserRepository userRepository, JwtService jwtService, AuthenticationManager authenticationManager, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.encoder = encoder;
    }

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        User user = new User();
        user.setEmail(registerRequest.getEmail());
        user.setPassword(encoder.encode(registerRequest.getPassword()));
        user.setRoles(registerRequest.getRoles());
        User savedUser = userRepository.save(user);
        String token = jwtService.generateToken(new UserSecurity(savedUser));
        return new AuthenticationResponse(token);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(),
                        authenticationRequest.getPassword());
        authenticationManager.authenticate(authenticationToken);
        UserSecurity userSecurity = userRepository.findUserByEmail(authenticationRequest.getEmail()).map(UserSecurity::new).get();
        String token = jwtService.generateToken(userSecurity);
        return new AuthenticationResponse(token);
    }
}
