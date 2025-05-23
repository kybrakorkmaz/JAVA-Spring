package com.korkmaz.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.korkmaz.security.user.Permission.*;
import static com.korkmaz.security.user.Role.ADMIN;
import static com.korkmaz.security.user.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)  // CSRF'i devre dışı bırakma
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**",
                                "/v2/api-docs",
                                "/v3/api-docs",
                                "/v3/api-docs/**",
                                "/swagger-resources",
                                "/swagger-resources/**",
                                "/configuration/ui",
                                "/configuration/security",
                                "/swagger-ui/**",
                                "/webjars/**",
                                "/swagger-ui.html").permitAll()  // Bu endpointlere izin ver

                        .requestMatchers("/api/v1/auth/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())

                        .requestMatchers(GET, "/api/v1/auth/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                        .requestMatchers(POST, "/api/v1/auth/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                        .requestMatchers(PUT, "/api/v1/auth/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                        .requestMatchers(DELETE, "/api/v1/auth/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                        /*.requestMatchers("/api/v1/auth/admin/**").hasRole(ADMIN.name())
                        .requestMatchers(GET, "/api/v1/auth/admin/**").hasAuthority(ADMIN_READ.name())
                        .requestMatchers(POST, "/api/v1/auth/admin/**").hasAuthority(ADMIN_CREATE.name())
                        .requestMatchers(PUT, "/api/v1/auth/admin/**").hasAuthority(ADMIN_UPDATE.name())
                        .requestMatchers(DELETE, "/api/v1/auth/admin/**").hasAuthority(ADMIN_DELETE.name())*/

                        .anyRequest().authenticated()  // Diğer tüm isteklerde kimlik doğrulama gereksinimi
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // Stateless oturum yönetimi
                )
                .authenticationProvider(authenticationProvider)  // AuthenticationProvider ekleme
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)  // JWT filter'ını ekleme
                .logout(logout ->
                        logout.logoutUrl("/api/v1/auth/logout")
                                .addLogoutHandler(logoutHandler)
                                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                );
        return http.build();  // HTTP yapılandırmasını döndür
    }
}
