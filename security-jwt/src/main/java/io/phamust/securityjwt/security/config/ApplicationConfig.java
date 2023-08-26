package io.phamust.securityjwt.security.config;

import io.phamust.securityjwt.appuser.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.ORIGIN;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.web.bind.annotation.RequestMethod.PATCH;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

        private final AppUserRepository appUserRepository;

    @Bean
    public UserDetailsService userDetailsService(){
        return username -> appUserRepository.findByEmail(username)
                .orElseThrow(()-> new UsernameNotFoundException("username not found"));
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    //Authentication manager is responsible to manage authentication,
    // Helping authenticate user using password and username,
    //Getting the default authentication provider from AuthenticationConfiguration by spring security.
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    //Data access object responsible to fetch user details and encode password ... here we used DaoAuthenticationProvider
   @Bean
    public AuthenticationProvider authenticationProvider(){
       DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
       authenticationProvider.setUserDetailsService(userDetailsService());
       authenticationProvider.setPasswordEncoder(passwordEncoder());
       return authenticationProvider;
   }

    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        config.setAllowedHeaders(Arrays.asList(
                ORIGIN,
                CONTENT_TYPE,
                ACCEPT,
                AUTHORIZATION
        ));
        config.setAllowedMethods(Arrays.asList(
                GET.name(),
                POST.name(),
                DELETE.name(),
                PUT.name(),
                PATCH.name()
        ));
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);

    }


}
