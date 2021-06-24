package br.com.alura.forum.config.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class TokenService {

	@Value("${forum.jwt.secret}")
	private String secret;
	
	@Value("${forum.jwt.expiration}")
	private String expiration;
	
	public String gerarToken(Authentication auth) {
		Usuario user = (Usuario) auth.getPrincipal();
		Date hoje = new Date();
		Date dateExpiration = new Date(hoje.getTime() + Long.parseLong(expiration));
		String token = Jwts.builder()
		//nome da aplicacao
		.setIssuer("YAL API")
		//data da geracao do token
		.setIssuedAt(hoje)
		//ID do usuario que esta se logando
		.setSubject(user.getId().toString())
		//data da expiracacao do token
		.setExpiration(dateExpiration)
		//indicando qual tipo de algoritmo para criptografar o token 
		.signWith(SignatureAlgorithm.HS256, secret)
		.compact();
		return token;
	}

	public boolean isValidToken(String token) {
		try {
			Jwts
			//metodo reposanvel pelo converter o token
			.parser()
			//informo minha chave de criptografia
			.setSigningKey(this.secret)
			//informo o toque para receber uma lista de Claims
			.parseClaimsJws(token);
			return true;
		}catch (Exception e) {
			return false;
		}
	}

	public Long getIdUsuario(String token) {
		Claims claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();
		return Long.parseLong(claims.getSubject());
	}
	
}
