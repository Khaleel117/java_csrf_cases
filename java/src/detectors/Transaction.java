@Entity
public class Transaction {
	@Id @GeneratedValue
    private Long id;
    private BigDecimal amount;
    private String type;
    private LocalDateTime timestamp;
    @ManyToOne
    private User fromUser;
    @ManyToOne
    private User toUser;
    private boolean isFlagged;
    private boolean isDeleted;

    // Getters, Setters
}
//--- Repository Interfaces ---
public interface UserRepository extends JpaRepository<User, Long> {
 Optional<User> findByUsername(String username);
}

public interface WalletRepository extends JpaRepository<Wallet, Long> {
 Optional<Wallet> findByUser(User user);
}

public interface TransactionRepository extends JpaRepository<Transaction, Long> {
 List<Transaction> findByFromUser(User user);
 List<Transaction> findByToUser(User user);
}

//--- Security Config (JWT + BCrypt) ---
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
 @Override
 protected void configure(HttpSecurity http) throws Exception {
     http.csrf().disable()
         .authorizeRequests()
         .antMatchers("/api/auth/**", "/swagger-ui/**").permitAll()
         .anyRequest().authenticated();
 }

 @Bean
 public PasswordEncoder passwordEncoder() {
     return new BCryptPasswordEncoder();
 }
}

