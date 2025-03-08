package com.School.API.Gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // Disable CSRF
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable) // Disable form login
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable) // Disable basic auth
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance()) // Stateless session management
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/actuator/**",
                                "/v3/api-docs/**",
                                "/auth/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html").permitAll() // Public Endpoints
                        .anyExchange().authenticated() // Everything else requires authentication
                )
                .build();
    }
}



/*
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // Disable CSRF
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable) // Disable form login
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable) // Disable basic auth
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance()) // Stateless session management
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/auth/**").permitAll() // Public login
                        .anyExchange().authenticated() // Everything else needs authentication
                )
                .build();
    }
}
*/