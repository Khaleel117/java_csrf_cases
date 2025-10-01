package security;
import controller.AuthController;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.mysql.cj.protocol.AuthenticationProvider;

@Configuration
public class FmsSecurityConfig {
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
		
	}
	protected void configure(HttpSecurity http) throws Exception {
	    http.csrf().disable()
	        .authorizeRequests()
	        .requestMatchers("/api/admin/**").hasRole("ADMIN")
	        .requestMatchers("/api/user/**").hasRole("USER")
	        .and()
	        .httpBasic();
	}
	@Bean
	public AuthenticationProvider authenticationProvider() {
	    return (AuthenticationProvider) new AuthController();
	}

}
