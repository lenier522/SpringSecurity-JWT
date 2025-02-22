package org.example.springsecurityjwt.config;

import org.example.springsecurityjwt.repository.Token;
import org.example.springsecurityjwt.repository.TokenRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final TokenRepository tokenRepository;

    /**
     * Constructor que inyecta las dependencias necesarias.
     *
     * @param jwtAuthFilter Filtro para validar tokens JWT.
     * @param authenticationProvider Proveedor de autenticación.
     * @param tokenRepository Repositorio para acceder a los tokens almacenados.
     */
    public SecurityConfig(JwtAuthFilter jwtAuthFilter, AuthenticationProvider authenticationProvider, TokenRepository tokenRepository) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
        this.tokenRepository = tokenRepository;
    }

    /**
     * Configura la cadena de filtros de seguridad.
     *
     * @param http Configuración de seguridad HTTP.
     * @return SecurityFilterChain configurado.
     * @throws Exception Si ocurre un error durante la configuración.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Deshabilita CSRF
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/auth/**")
                                .permitAll() // Permite acceso público a los endpoints de autenticación
                                .anyRequest()
                                .authenticated()) // Requiere autenticación para cualquier otra solicitud
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Configura la gestión de sesiones como sin estado
                .authenticationProvider(authenticationProvider) // Configura el proveedor de autenticación
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) // Añade el filtro JWT antes del filtro de autenticación por usuario y contraseña
                .logout(logout ->
                        logout.logoutUrl("/auth/logout") // Configura el endpoint de logout
                                .addLogoutHandler((request, response, authentication) -> {
                                    final var authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
                                    logout(authHeader); // Maneja el logout invalidando el token
                                })
                                .logoutSuccessHandler(((request, response, authentication) ->
                                        SecurityContextHolder.clearContext())) // Limpia el contexto de seguridad después del logout
                );

        return http.build();
    }

    /**
     * Invalida el token JWT durante el logout.
     *
     * @param token Token JWT a invalidar.
     * @throws IllegalArgumentException Si el token es inválido.
     */
    private void logout(final String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid Token");
        }
        final String jwtToken = token.substring(7);
        final Token foundToken = tokenRepository.findByToken(jwtToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid Token"));
        foundToken.setExpired(true); // Marca el token como expirado
        foundToken.setRevoked(true); // Marca el token como revocado
        tokenRepository.save(foundToken); // Guarda los cambios en la base de datos
    }
}