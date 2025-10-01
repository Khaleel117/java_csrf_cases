package com.coding;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class Security extends WebSecurityConfigurerAdapter {
	
	@Autowired
	UserDetailsService userDetailsService;
	
	@Autowired
	private RequestFilter jwtrequestfilter;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		/*auth.inMemoryAuthentication().withUser("user1").password("{noop}1234").roles("admin")
		.and().withUser("user2").password("{noop}5678").roles("user");*/
		auth.userDetailsService(userDetailsService);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		
		http.csrf().disable()
		.authorizeRequests().antMatchers("/loginUserJwt").permitAll()
		.antMatchers(HttpMethod.OPTIONS).permitAll()
		 .antMatchers("/api/etudiants/**").permitAll()//enleve cette ligne si tu veux utiliser token pour aceder au api etudiant
		 .antMatchers(HttpMethod.POST, "/api/etudiants/**").hasAuthority("ADMIN")
		 .antMatchers("/api/professeurs/**").permitAll()//enleve cette ligne si tu veux utiliser token pour aceder au api prof
		 .antMatchers(HttpMethod.POST,"/api/professeurs/**").hasAuthority("ADMIN")
		 .antMatchers("/api/annonce/**").permitAll()//enleve cette ligne si tu veux utiliser token pour aceder au api etudiant
		 .antMatchers(HttpMethod.POST,"/api/annonce/**").hasAuthority("ADMIN")
		 .antMatchers("/api/filliere/**").permitAll()
		 .antMatchers(HttpMethod.POST,"/api/filliere/**").hasAuthority("ADMIN")
		 .antMatchers("/api/user/**").permitAll()
		 .antMatchers(HttpMethod.POST,"/api/user/**").hasAuthority("ADMIN")
		 .antMatchers("/api/directeurG/**").permitAll()
		 .antMatchers(HttpMethod.POST,"/api/directeurG/**").hasAuthority("ADMIN")
		.anyRequest().authenticated()
		.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and().addFilterBefore(jwtrequestfilter, UsernamePasswordAuthenticationFilter.class);
	}
	
	
	@Bean
	public BCryptPasswordEncoder passEncoder()
	{
		return new BCryptPasswordEncoder();
	}
	
	
	@Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		// TODO Auto-generated method stub
		return super.authenticationManager();
	}

	
	
	
	

}
