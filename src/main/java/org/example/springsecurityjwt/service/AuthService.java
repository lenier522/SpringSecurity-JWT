package org.example.springsecurityjwt.service;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwt.controller.LoginRequest;
import org.example.springsecurityjwt.controller.RegisterRequest;
import org.example.springsecurityjwt.controller.TokenResponse;
import org.example.springsecurityjwt.repository.Token;
import org.example.springsecurityjwt.repository.TokenRepository;
import org.example.springsecurityjwt.usuario.User;
import org.example.springsecurityjwt.usuario.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Constructor que inyecta las dependencias necesarias.
     *
     * @param userRepository Repositorio para acceder a los datos de los usuarios.
     * @param tokenRepository Repositorio para acceder a los tokens almacenados.
     * @param passwordEncoder Codificador de contraseñas.
     * @param jwtService Servicio para manejar operaciones relacionadas con JWT.
     * @param authenticationManager Gestor de autenticación.
     */
    public AuthService(UserRepository userRepository, TokenRepository tokenRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    /**
     * Registra un nuevo usuario y genera tokens JWT.
     *
     * @param request Solicitud de registro que contiene los detalles del usuario.
     * @return TokenResponse con el token de acceso y el token de refresco.
     */
    public TokenResponse register(RegisterRequest request) {
        var user = User.builder()
                .name(request.name())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateResfreshToken(user);
        savedUserToken(savedUser, jwtToken);
        return new TokenResponse(jwtToken, refreshToken);
    }

    /**
     * Autentica un usuario y genera tokens JWT.
     *
     * @param request Solicitud de inicio de sesión que contiene las credenciales del usuario.
     * @return TokenResponse con el token de acceso y el token de refresco.
     */
    public TokenResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
        var user = userRepository.findByEmail(request.email())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateResfreshToken(user);
        revokeAllUserTokens(user);
        savedUserToken(user, jwtToken);
        return new TokenResponse(jwtToken, refreshToken);
    }

    /**
     * Revoca todos los tokens válidos de un usuario.
     *
     * @param user Usuario cuyos tokens se van a revocar.
     */
    private void revokeAllUserTokens(final User user) {
        final List<Token> validUserTokens = tokenRepository
                .findAllValidIsFalseOrRevokedIsfalseByuserId(user.getId());
        if (!validUserTokens.isEmpty()) {
            for (final Token token : validUserTokens) {
                token.setExpired(true);
                token.setRevoked(true);
            }
            tokenRepository.saveAll(validUserTokens);
        }
    }

    /**
     * Guarda un token JWT en la base de datos.
     *
     * @param user Usuario asociado al token.
     * @param jwtToken Token JWT a guardar.
     */
    private void savedUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(Token.TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    /**
     * Renueva el token de acceso utilizando el token de refresco.
     *
     * @param authHeader Encabezado de autorización que contiene el token de refresco.
     * @return TokenResponse con el nuevo token de acceso y el token de refresco.
     * @throws IllegalArgumentException Si el token de refresco es inválido.
     * @throws UsernameNotFoundException Si no se encuentra el usuario asociado al token.
     */
    public TokenResponse refreshToken(final String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid Token");
        }
        final String refreshToken = authHeader.substring(7);
        final String userEmail = jwtService.extractUsername(refreshToken);

        if (userEmail == null) {
            throw new IllegalArgumentException("Invalid Refresh Token");
        }
        final User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException(userEmail));

        if (!jwtService.isTokenValid(refreshToken, user)) {
            throw new IllegalArgumentException("Invalid Refresh Token");
        }
        final String accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        savedUserToken(user, accessToken);
        return new TokenResponse(accessToken, refreshToken);
    }
}