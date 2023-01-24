package com.example.springsecurityjwt.configuration.jwt;

import com.example.springsecurityjwt.configuration.model.UserSecurity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private String SECRET_KEY = "aGVsbDAgdGhpcyBzdHJpbmcgaXMgQCB0MHAgc2VjcmV0IHN0cmluZyB5MHUgd2lsbCBldmVyIHNlZSBpbiB1ciBsaWZlCg==";

    public String getUserEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimFunctionResolver) {
        Claims claims = extractAllClaims(token);
        return claimFunctionResolver.apply(claims);
    }

    public String generateToken(UserSecurity userSecurity) {
        Instant now = Instant.now();
        return Jwts.
                builder().
//                setHeader(Map.of(Header.TYPE, Header.JWT_TYPE)).
                setSubject(userSecurity.getUsername()).
                setExpiration(Date.from(now.plus(1, ChronoUnit.DAYS))).
                setIssuedAt(Date.from(now)).
                addClaims(Map.of("roles", userSecurity.getAuthorities())).
                signWith(getSigningKey()).
                compact();
    }

    private Claims extractAllClaims(String token) {
        // in this chunk of code we validate the token also using the signing key we used to sing it while creating it.
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        return userDetails.getUsername().equals(getUserEmail(token)) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(Date.from(Instant.now()));
    }

    private Key getSigningKey() {
        // decode the encryption key before generating the signing key
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
