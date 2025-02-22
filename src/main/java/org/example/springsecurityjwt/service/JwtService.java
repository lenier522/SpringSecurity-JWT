package org.example.springsecurityjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.example.springsecurityjwt.usuario.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey; // Clave secreta para firmar los tokens JWT
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration; // Tiempo de expiración del token de acceso
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration; // Tiempo de expiración del token de refresco

    /**
     * Extrae el nombre de usuario (email) de un token JWT.
     *
     * @param token Token JWT del cual extraer el nombre de usuario.
     * @return El nombre de usuario (email) contenido en el token.
     */
    public String extractUsername(final String token) {
        final Claims jwtToken = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return jwtToken.getSubject();
    }

    /**
     * Genera un token de acceso JWT para un usuario.
     *
     * @param user Usuario para el cual se genera el token.
     * @return Token de acceso JWT.
     */
    public String generateToken(final User user) {
        return buildToken(user, jwtExpiration);
    }

    /**
     * Genera un token de refresco JWT para un usuario.
     *
     * @param user Usuario para el cual se genera el token.
     * @return Token de refresco JWT.
     */
    public String generateResfreshToken(final User user) {
        return buildToken(user, refreshExpiration);
    }

    /**
     * Construye un token JWT con los datos proporcionados.
     *
     * @param user Usuario para el cual se genera el token.
     * @param expiration Tiempo de expiración del token.
     * @return Token JWT generado.
     */
    private String buildToken(final User user, final long expiration) {
        return Jwts.builder()
                .id(user.getId().toString()) // ID del usuario
                .claims(Map.of("name", user.getName())) // Claims adicionales (nombre del usuario)
                .subject(user.getEmail()) // Subject (email del usuario)
                .issuedAt(new Date(System.currentTimeMillis())) // Fecha de emisión
                .expiration(new Date(System.currentTimeMillis() + expiration)) // Fecha de expiración
                .signWith(getSignInKey()) // Firma el token con la clave secreta
                .compact(); // Convierte el token a una cadena compacta
    }

    /**
     * Obtiene la clave secreta para firmar los tokens JWT.
     *
     * @return SecretKey generada a partir de la clave secreta.
     */
    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey); // Decodifica la clave secreta desde Base64
        return Keys.hmacShaKeyFor(keyBytes); // Genera una clave HMAC
    }

    /**
     * Verifica si un token JWT es válido para un usuario.
     *
     * @param token Token JWT a validar.
     * @param user Usuario para el cual se valida el token.
     * @return true si el token es válido, false en caso contrario.
     */
    public boolean isTokenValid(final String token, final User user) {
        final String username = extractUsername(token);
        return (username.equals(user.getEmail())) && !isTokenExpired(token); // Verifica que el nombre de usuario coincida y que el token no esté expirado
    }

    /**
     * Verifica si un token JWT está expirado.
     *
     * @param token Token JWT a verificar.
     * @return true si el token está expirado, false en caso contrario.
     */
    private boolean isTokenExpired(final String token) {
        return extractExpiration(token).before(new Date()); // Compara la fecha de expiración con la fecha actual
    }

    /**
     * Extrae la fecha de expiración de un token JWT.
     *
     * @param token Token JWT del cual extraer la fecha de expiración.
     * @return Fecha de expiración del token.
     */
    private Date extractExpiration(final String token) {
        final Claims jwtToken = Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return jwtToken.getExpiration(); // Devuelve la fecha de expiración
    }
}