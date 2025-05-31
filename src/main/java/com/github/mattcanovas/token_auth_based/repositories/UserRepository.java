package com.github.mattcanovas.token_auth_based.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.github.mattcanovas.token_auth_based.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
}
