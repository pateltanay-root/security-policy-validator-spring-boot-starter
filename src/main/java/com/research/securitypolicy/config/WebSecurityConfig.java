package com.research.securitypolicy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {

    @Bean
    SecurityFilterChain webSecurityFilterChain(
            HttpSecurity http)
            throws Exception {

        http
                .csrf(csrf ->
                        csrf.disable()
                )

                .authorizeHttpRequests(auth ->
                        auth
                                .requestMatchers(
                                        "/",
                                        "/index.html",
                                        "/style.css",
                                        "/app.js",
                                        "/api/analysis"
                                )
                                .permitAll()

                                .anyRequest()
                                .permitAll()
                )

                .formLogin(form ->
                        form.disable()
                )

                .httpBasic(basic ->
                        basic.disable()
                );

        return http.build();
    }
}