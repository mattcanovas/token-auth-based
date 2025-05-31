package com.github.mattcanovas.token_auth_based.records;

import com.github.mattcanovas.token_auth_based.enums.UserRole;

public record CreateUserRecord(
    String username,
    String password, 
    String email,
    UserRole role
) {
    
}
