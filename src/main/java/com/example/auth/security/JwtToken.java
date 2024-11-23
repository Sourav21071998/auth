package com.example.auth.security;

import java.security.Key;
import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtToken {
	
	private Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
	
	public String generateToken(final String username) {
		return Jwts.builder()
				.setSubject(username)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000*60*60))
				.signWith(key)
				.compact();
	}
	
	public Claims extractClaims(final String token) {
		return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
	}
	
	public String extractUsername(final String token) {
		return extractClaims(token).getSubject();
	}
	
	public Date extractExpiration(final String token) {
		return extractClaims(token).getExpiration();
	}
	
	public boolean validateToken(final String token, UserDetails userDetails) {
		return extractUsername(token).equals(userDetails.getUsername()) && extractExpiration(token).after(new Date());
	}

}
