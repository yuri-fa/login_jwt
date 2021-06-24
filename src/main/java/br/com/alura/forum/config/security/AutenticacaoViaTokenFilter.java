package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;

//classe declarada no filter da SecurityConfiguration

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter{
	
	private static final String BEARER = "Bearer ";
	
	private TokenService tokenService;
	
	private UsuarioRepository usuarioRepository;

	public AutenticacaoViaTokenFilter(TokenService tokenService,UsuarioRepository usuarioRepository) {
		this.tokenService = tokenService;
		this.usuarioRepository = usuarioRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token = getToken(request);
		boolean isValid = tokenService.isValidToken(token);
		if (isValid) {
			autenticarCliente(token);
		}
		
		filterChain.doFilter(request, response);
	}

	private void autenticarCliente(String token) {
		//pegando o id do usuario no token
		Long idUsuario = tokenService.getIdUsuario(token);
		//consultando usuario no token
		Usuario usuario = usuarioRepository.findById(idUsuario).get();
		//autenticando toda vez que recebe uma nova requisição
		UsernamePasswordAuthenticationToken passwordAuthenticationToken = new UsernamePasswordAuthenticationToken(usuario,null,usuario.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(passwordAuthenticationToken);
	}

	private String getToken(HttpServletRequest request) {
		String token = request.getHeader("Authorization");
		
		if (token == null || token.isEmpty() || !token.startsWith(BEARER) ) {
			return null;
		}
		return token.replace(BEARER, "");
	}

}
