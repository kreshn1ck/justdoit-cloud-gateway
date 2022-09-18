package com.ubt.cloud.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
/*import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;*/
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
/*import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;*/

/*@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)*/
public class SecurityTokenConfig /*extends WebSecurityConfigurerAdapter*/ {

	/*private JwtConfig jwtConfig;

	public SecurityTokenConfig(JwtConfig jwtConfig) {
		this.jwtConfig = jwtConfig;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
				.and()
				.addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
				// .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
				.authorizeRequests()
				// .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
				// AuthenticationController
				.antMatchers(HttpMethod.OPTIONS, "/backend/auth/login").permitAll()
				.antMatchers(HttpMethod.POST, "/backend/auth/login").permitAll()
				.antMatchers(HttpMethod.GET, "/backend/auth/refresh-token/**").permitAll()

				// UserController
				.antMatchers(HttpMethod.POST, "/backend/users/forgot-password").permitAll()
				.antMatchers(HttpMethod.GET, "/backend/reset-password/**").permitAll()
				.antMatchers(HttpMethod.POST, "/backend/reset-password/**").permitAll()
				.antMatchers(HttpMethod.GET, "/backend/user-confirmation/**").permitAll()
				.antMatchers(HttpMethod.POST, "/backend/sign-up/**").permitAll()
				.antMatchers(HttpMethod.GET, "/backend/test").permitAll()

				.antMatchers("/api/*").permitAll()
				.antMatchers("/v2/api-docs",
						"/swagger-resources/**",
						"/swagger-ui.html",
						"/webjars/**",
						"/**",
						"/swagger.json").permitAll()
				.anyRequest().authenticated();
				// .and()
				// .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}*/

	/*@Bean
	public JwtConfig jwtConfig() {
		return new JwtConfig();
	}*/
	/*@Autowired
	private JwtConfig jwtConfig;
 
	@Override
  	protected void configure(HttpSecurity http) throws Exception {
    	   http
		.csrf().disable()
		    // make sure we use stateless session; session won't be used to store user's state.
	 	    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 	
		.and()
		    // handle an authorized attempts 
		    .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)) 	
		.and()
		   // Add a filter to validate the tokens with every request
		   .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
		// authorization requests config
		.authorizeRequests()
		   // allow all who are accessing "auth" service
		   .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()  
		   // must be an admin if trying to access admin area (authentication is also required here)
		   .antMatchers("/gallery" + "/admin/**").hasRole("ADMIN")
		   // Any other request must be authenticated
		   .anyRequest().authenticated(); 
	}*/
	
	/*@Bean
  	public JwtConfig jwtConfig() {
    	   return new JwtConfig();
  	}*/
}