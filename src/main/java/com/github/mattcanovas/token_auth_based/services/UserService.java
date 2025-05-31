package com.github.mattcanovas.token_auth_based.services;

import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.github.mattcanovas.token_auth_based.entities.Role;
import com.github.mattcanovas.token_auth_based.entities.User;
import com.github.mattcanovas.token_auth_based.records.AuthenticateUserRecord;
import com.github.mattcanovas.token_auth_based.records.CreateUserRecord;
import com.github.mattcanovas.token_auth_based.records.RecoveryJwtTokenRecord;
import com.github.mattcanovas.token_auth_based.repositories.UserRepository;
import com.github.mattcanovas.token_auth_based.security.authentication.JwtTokenService;
import com.github.mattcanovas.token_auth_based.security.configuration.SecurityConfiguration;
import com.github.mattcanovas.token_auth_based.security.user.details.UserDetailsImpl;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;

    private final AuthenticationManager authenticationmanager;

    private final JwtTokenService jwtTokenService;

    private final SecurityConfiguration securityConfiguration;

    public RecoveryJwtTokenRecord authenticateUser(AuthenticateUserRecord record) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                record.username(), record.password());
        Authentication authentication = authenticationmanager.authenticate(usernamePasswordAuthenticationToken);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        return new RecoveryJwtTokenRecord(jwtTokenService.generateToken(userDetails));
    }

    public void create(CreateUserRecord record) {
        User user = User.builder()
                .username(record.username())
                .password(securityConfiguration.passwordEncoder().encode(record.password()))
                .email(record.email())
                .roles(List.of(Role.builder().userRole(record.role()).build()))
                .build();

        this.repository.save(user);
    }

}
