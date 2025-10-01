@Configuration
class BasicAuthConfig {
  @Bean SecurityFilterChain filter(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .authorizeHttpRequests(req -> req
           .requestMatchers("/admin/kc/**").authenticated()
           .anyRequest().permitAll())
        .httpBasic(Customizer.withDefaults());
    return http.build();
  }
}
