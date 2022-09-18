package com.ubt.cloud.gateway.security;

import com.ubt.cloud.gateway.security.exception.TokenValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RefreshScope
@Component
public class JwtTokenAuthenticationFilter implements GatewayFilter {

	@Autowired
	private RouterValidator routerValidator;
	@Autowired
	private JwtUtil jwtUtil;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = exchange.getRequest();

		if (routerValidator.isSecured.test(request)) {
			if (this.isAuthMissing(request))
				return this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);

			String token = this.getAuthHeader(request).replace("Bearer ","");

			try {
				jwtUtil.validateToken(token);
			} catch (TokenValidationException e) {
				return this.onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
			}

			JwtClaims claims = jwtUtil.getAllClaimsFromToken(token);
			exchange.getRequest().mutate()
					.header("userId", String.valueOf(claims.getUserId()))
					.header("email", claims.getUserEmail())
					.header("username", claims.getUsername())
					.build();
		}
		return chain.filter(exchange);
	}


	/*PRIVATE*/

	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {

		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		return response.setComplete();
	}

	private String getAuthHeader(ServerHttpRequest request) {
		return request.getHeaders().getOrEmpty("Authorization").get(0);
	}

	private boolean isAuthMissing(ServerHttpRequest request) {
		return !request.getHeaders().containsKey("Authorization");
	}

	/*private final JwtConfig jwtConfig;
	
	public JwtTokenAuthenticationFilter(JwtConfig jwtConfig) {
		this.jwtConfig = jwtConfig;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		
		String header = request.getHeader(jwtConfig.getHeader());
		
		if(header == null || !header.startsWith(jwtConfig.getPrefix())) {
			chain.doFilter(request, response);
			return;
		}
		
		String token = header.replace(jwtConfig.getPrefix(), "");
		try {
			Claims jwtClaims = Jwts.parser()
					.setSigningKey(jwtConfig.getSecret().getBytes())
					.parseClaimsJws(token)
					.getBody();
			JwtClaims claims = new JwtClaims(jwtClaims);

			Long userId = claims.getUserId();
			String email = claims.getUserEmail();
			String username = claims.getUsername();
			if(username != null) {
				 UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(email, userId, null);
				 SecurityContextHolder.getContext().setAuthentication(auth);
			}
		} catch (Exception e) {
			SecurityContextHolder.clearContext();
		}
		
		chain.doFilter(request, response);
	}*/

}