package com.ngh.springsecurity.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String secretKey="sWDu8XfcQ3IBYDlsXp20OxKNFJQajfdkan62x9i6nSzs4c";

    public String extractUserName(String jwt) {
        return extractClaim(jwt,Claims::getSubject);
    }

    public <T> T extractClaim(String jwt, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(jwt);
        return claimsResolver.apply(claims);
    }


    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){
        return  Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    public boolean isTokenValid(String jwt,UserDetails userDetails){
        final String username = extractUserName(jwt);
        return (username.equals(userDetails.getUsername()))&&!isTokenExpired(jwt);
    }

    private boolean isTokenExpired(String jwt) {
        return extractExpiration(jwt).before(new Date());
    }

    private Date extractExpiration(String jwt) {
        return extractClaim(jwt,Claims::getExpiration);
    }

    public Claims extractAllClaims(String jwt){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJwt(jwt)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
