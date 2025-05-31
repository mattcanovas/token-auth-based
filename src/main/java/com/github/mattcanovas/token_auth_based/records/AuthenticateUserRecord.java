package com.github.mattcanovas.token_auth_based.records;

public record AuthenticateUserRecord(
    String email,
    String password
) {
    
}
