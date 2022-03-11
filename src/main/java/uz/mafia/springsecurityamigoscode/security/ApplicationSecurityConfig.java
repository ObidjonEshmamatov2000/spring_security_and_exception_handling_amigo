package uz.mafia.springsecurityamigoscode.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import uz.mafia.springsecurityamigoscode.auth.ApplicationUserService;
import uz.mafia.springsecurityamigoscode.jwt.JwtConfig;
import uz.mafia.springsecurityamigoscode.jwt.JwtTokenVerifier;
import uz.mafia.springsecurityamigoscode.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import javax.crypto.SecretKey;

import static uz.mafia.springsecurityamigoscode.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, JwtConfig jwtConfig, SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // jwt stateless
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails user = User.builder()
//                .username("star")
//                .password(passwordEncoder.encode("star"))
//                .roles(STUDENT.name())
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//        UserDetails admin = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("linda"))
//                .roles(ADMIN.name())
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//        UserDetails admin_trainee = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("tom"))
//                .roles(ADMIN_TRAINEE.name())
//                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
//                .build();
//        return new InMemoryUserDetailsManager(user, admin, admin_trainee);
//    }
}
