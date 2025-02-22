package org.example.springsecurityjwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.example.springsecurityjwt.repository.Token;
import org.example.springsecurityjwt.repository.TokenRepository;
import org.example.springsecurityjwt.service.JwtService;
import org.example.springsecurityjwt.usuario.User;
import org.example.springsecurityjwt.usuario.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    /**
     * Constructor que inyecta las dependencias necesarias.
     *
     * @param jwtService Servicio para manejar operaciones relacionadas con JWT.
     * @param userDetailsService Servicio para cargar los detalles del usuario.
     * @param tokenRepository Repositorio para acceder a los tokens almacenados.
     * @param userRepository Repositorio para acceder a los datos de los usuarios.
     */
    public JwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService, TokenRepository tokenRepository,
                         UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
    }

    /**
     * Método que se ejecuta en cada solicitud para validar el token JWT y autenticar al usuario.
     *
     * @param request La solicitud HTTP.
     * @param response La respuesta HTTP.
     * @param filterChain Cadena de filtros para continuar con la siguiente operación.
     * @throws ServletException Si ocurre un error en el servlet.
     * @throws IOException Si ocurre un error de entrada/salida.
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Si la solicitud es para el endpoint de autenticación, se ignora el filtro
        if (request.getServletPath().contains("/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Obtiene el encabezado de autorización
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Si no hay encabezado de autorización o no comienza con "Bearer ", se ignora el filtro
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extrae el token JWT del encabezado
        final String jwtToken = authHeader.substring(7);

        // Extrae el email del token JWT
        final String email = jwtService.extractUsername(jwtToken);

        // Si no se puede extraer el email o ya hay una autenticación en el contexto, se ignora el filtro
        if (email == null || SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Busca el token en la base de datos
        final Token token = tokenRepository.findByToken(jwtToken)
                .orElse(null);

        // Si el token no existe, está expirado o revocado, se ignora el filtro
        if (token == null || token.isExpired() || token.isRevoked()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Carga los detalles del usuario basado en el email
        final UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);

        // Busca el usuario en la base de datos
        final Optional<User> user = userRepository.findByEmail(userDetails.getUsername());

        // Si el usuario no existe, se ignora el filtro
        if (user.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Valida el token JWT
        final boolean isTokenValid = jwtService.isTokenValid(jwtToken, user.get());

        // Si el token no es válido, se ignora el filtro
        if (!isTokenValid) {
            filterChain.doFilter(request, response);
            return;
        }

        // Crea un objeto de autenticación y lo establece en el contexto de seguridad
        final var authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // Continúa con la cadena de filtros
        filterChain.doFilter(request, response);
    }
}