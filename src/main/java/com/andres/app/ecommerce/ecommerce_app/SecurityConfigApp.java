package com.andres.app.ecommerce.ecommerce_app;

import com.andres.app.ecommerce.ecommerce_app.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfigApp {

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //Confirguracion de permisos de ingreso
   /* @Bean
    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        try {
        return httpSecurity.authorizeHttpRequests(authz -> authz
                        .anyRequest()
                        .authenticated())
                        .addFilter(new JwtAuthenticationFilter(this.authenticationManager()))
                        .csrf(config -> config.disable())
                        .sessionManagement(managment -> managment.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                        .build();
        }catch (Exception e){
            throw  new RuntimeException("Error en la configuracion de SecurityFilterChain", e);
        }


    }*/
    @Bean
    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        try {
            httpSecurity
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(authz -> authz
                            // Permitir acceso a endpoints de Swagger
                            .requestMatchers(
                                    "/v3/api-docs/**",
                                    "/swagger-ui/**",
                                    "/swagger-ui.html",
                                    "/swagger-resources/**",
                                    "/webjars/**"
                            ).permitAll()
                            // Requerir autenticación para cualquier otra solicitud
                            .anyRequest().authenticated()
                    )
                    .addFilter(new JwtAuthenticationFilter(authenticationManager()));

            return httpSecurity.build();
        } catch (Exception e){
            throw new RuntimeException("Error en la configuracion de SecurityFilterChain", e);
        }
    }

}
