package com.ubt.cloud.gateway.security;

import com.ubt.cloud.gateway.security.exception.TokenValidationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    @Value("${jwt.secret:ThisIsASecret}")
    private String secret;

    public JwtClaims getAllClaimsFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
        return new JwtClaims(claims);
    }

    public void validateToken(final String token) throws TokenValidationException {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
        } catch (MalformedJwtException ex) {
            throw new TokenValidationException("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            throw new TokenValidationException("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            throw new TokenValidationException("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            throw new TokenValidationException("JWT claims string is empty.");
        } catch (Exception e) {
            throw new TokenValidationException("Invalid exception.");
        }
    }
}
