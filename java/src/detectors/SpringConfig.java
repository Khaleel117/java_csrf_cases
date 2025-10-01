package com.carazem;


import com.carazem.auth.AuthFilter;
import com.carazem.config.ConfigService;
import com.carazem.config.Keys;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;

import javax.annotation.PostConstruct;
import java.io.FileNotFoundException;

@SpringBootApplication
@PropertySource("classpath:application.properties")
@EnableWebSecurity
public class SpringConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    ConfigService configService;

    @PostConstruct
    public void init() throws FileNotFoundException {
        Flyway flyway = new Flyway();
        flyway.setDataSource(configService.get(Keys.DB_URL), configService.get(Keys.DB_USER), configService.get(Keys.DB_PASSWORD));
        flyway.migrate();
    }

    @Bean
    public FirebaseAuth firebaseAuth() {
        FirebaseOptions options = new FirebaseOptions.Builder()
                .setServiceAccount(this.getClass().getResourceAsStream(configService.get(Keys.FIREBASE_KEY_PATH)))
                .setDatabaseUrl(configService.get(Keys.FIREBASE_DB_URL))
                .build();
        FirebaseApp.initializeApp(options);
        return FirebaseAuth.getInstance();
    }


    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedHeader("*");
        config.addAllowedOrigin("*");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("DELETE");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    public MultipartResolver multipartResolver() {
        return new CommonsMultipartResolver();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/rides").permitAll()
                .antMatchers(HttpMethod.GET, "/login").authenticated() // TODO remove after testing
                //.antMatchers("/**").authenticated() // TODO uncomment after testing
                .and()
                .addFilterBefore(new AuthFilter(firebaseAuth()), BasicAuthenticationFilter.class)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

}