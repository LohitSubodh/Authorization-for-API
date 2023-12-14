package security;

import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import service.UserService;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity

public class WebSecurityConfig implements WebSecurityConfigurer {
    @Autowired
    private UserService userDetailsService;

    @Autowired
    private JwtAuthEntryPoint unauthorizedHandler;
    @Autowired
    private  JwtAuthTokenFilter jwtAuthTokenFilter;

    @Bean
    public JwtAuthTokenFilter authenticationJwtTokenFilter() {
        return new JwtAuthTokenFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors(customizer -> {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            corsConfiguration.setAllowedOrigins(List.of("*"));
            corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            corsConfiguration.setAllowedHeaders(List.of("*"));
            corsConfiguration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type"));
            customizer.configurationSource(request -> corsConfiguration);
        }).csrf(customizer -> {
            customizer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        }).authorizeRequests(customizer -> {
            customizer.antMatchers("/api/auth/**").permitAll();
            customizer.antMatchers("/api/test/public/**").permitAll();
            customizer.antMatchers("/api/test/private/**").hasRole("USER");
        }).exceptionHandling(customizer -> {
            customizer.authenticationEntryPoint(unauthorizedHandler);
        }).sessionManagement(customizer -> {
            customizer.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });

        http.addFilterBefore(jwtAuthTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void init(SecurityBuilder builder) throws Exception {

    }

    @Override
    public void configure(SecurityBuilder builder) throws Exception {

    }
}
