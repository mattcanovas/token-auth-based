package com.github.mattcanovas.token_auth_based.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.mattcanovas.token_auth_based.records.AuthenticateUserRecord;
import com.github.mattcanovas.token_auth_based.records.CreateUserRecord;
import com.github.mattcanovas.token_auth_based.records.RecoveryJwtTokenRecord;
import com.github.mattcanovas.token_auth_based.services.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService service;

    @PostMapping("/login")
    public ResponseEntity<RecoveryJwtTokenRecord> authenticateUser(@RequestBody AuthenticateUserRecord record) {
        RecoveryJwtTokenRecord response = service.authenticateUser(record);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<Void> registerUser(@RequestBody CreateUserRecord record) {
        service.create(record);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return new ResponseEntity<>("Autenticado com sucesso.", HttpStatus.OK);
    }

    @GetMapping("/test/administrator")
    public ResponseEntity<String> testAdministrador() {
        return new ResponseEntity<>("Administrador autenticado com sucesso.", HttpStatus.OK);
    }

    @GetMapping("/test/customer")
    public ResponseEntity<String> testCustomer() {
        return new ResponseEntity<>("Cliente autenticado com sucesso.", HttpStatus.OK);
    }

}
