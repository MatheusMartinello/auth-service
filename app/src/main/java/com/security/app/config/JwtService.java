package com.security.app.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  private static String SECRET_KEY = "16F13E66598B5155852DFD21F2BB4";

  public <T> T extractionClaim(String jwtToken, Function<Claims, T> claimsResolve) {
    final Claims claims = extractAllClaims(jwtToken);
    return claimsResolve.apply(claims);
  }

  private Claims extractAllClaims(String jwtToken) {
    return (Claims)
        Jwts.parserBuilder().setSigningKey(getSigningkey()).build().parse(jwtToken).getBody();
  }

  public String extractUserName(String jwtToken) {
    return extractionClaim(jwtToken, Claims::getSubject);
  }

  private Key getSigningkey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  public String generateToken(Map<String, Object> extractClaims, UserDetails userDetails) {
    return Jwts.builder()
        .setClaims(extractClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
        .signWith(getSigningkey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public Boolean isTokenValid(String jwtToken, UserDetails userDetails) {
    return userDetails.getUsername().equals(extractUserName(jwtToken)) && !isTokenExpired(jwtToken);
  }

  private Boolean isTokenExpired(String jwtToken) {
    return extractExpiration(jwtToken).before(new Date());
  }

  private Date extractExpiration(String jwtToken) {
    return extractionClaim(jwtToken, Claims::getExpiration);
  }
}
