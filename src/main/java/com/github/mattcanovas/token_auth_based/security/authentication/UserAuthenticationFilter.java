package com.github.mattcanovas.token_auth_based.security.authentication;

import java.io.IOException;
import java.util.Arrays;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.mattcanovas.token_auth_based.entities.User;
import com.github.mattcanovas.token_auth_based.repositories.UserRepository;
import com.github.mattcanovas.token_auth_based.security.configuration.SecurityConfiguration;
import com.github.mattcanovas.token_auth_based.security.user.details.UserDetailsImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class UserAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (isNotEndpointPublic(request)) {
            String token = getTokenFromHeader(request);
            if (token != null) {
                String subject = jwtTokenService.getSubjectFromToken(token);
                User user = this.userRepository.findByUsername(subject)
                        .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
                UserDetailsImpl userDetails = new UserDetailsImpl(user);

                Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), null,
                        userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                throw new RuntimeException("Token não informado.");
            }
        }
        filterChain.doFilter(request, response);
    }

    private String getTokenFromHeader(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null) {
            return authorizationHeader.replace("Bearer ", "");
        }
        return null;
    }

    private Boolean isNotEndpointPublic(HttpServletRequest request) {
        return !Arrays.asList(SecurityConfiguration.ENDPOINTS_WITH_AUTHENTICATION_NOT_REQUIRED).contains(request.getRequestURI());
    }

}
