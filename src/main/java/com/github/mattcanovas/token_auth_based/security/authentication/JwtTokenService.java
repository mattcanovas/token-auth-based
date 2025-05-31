package com.github.mattcanovas.token_auth_based.security.authentication;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.github.mattcanovas.token_auth_based.security.user.details.UserDetailsImpl;

@Service
public class JwtTokenService {

    private static final String SECRET_KEY = "fd4b0940a485521b6daf4ab0719beb64fc3442c7f283f6a0e18748b355921dd1";

    private static final String ISSUER = "vello-api";

    public String generateToken(UserDetailsImpl user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

            return JWT.create()
                    .withIssuer(ISSUER)
                    .withIssuedAt(getCreationDate())
                    .withExpiresAt(getExpirationDate())
                    .withSubject(user.getUsername())
                    .sign(algorithm);

        } catch (JWTCreationException e) {
            throw new JWTCreationException("Erro ao gerar token.", e);
        }
    }

    private Instant getCreationDate() {
        return ZonedDateTime.now(ZoneId.of("America/Sao_Paulo")).toInstant();
    }

    private Instant getExpirationDate() {
        return ZonedDateTime.now(ZoneId.of("America/Sao_Paulo")).plusHours(4).toInstant();
    }

}
