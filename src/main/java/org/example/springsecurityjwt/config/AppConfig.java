package org.example.springsecurityjwt.config;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwt.usuario.User;
import org.example.springsecurityjwt.usuario.UserRepository;
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

@Configuration
public class AppConfig {

    private final UserRepository userRepository;

    /**
     * Constructor que inyecta la dependencia de UserRepository.
     *
     * @param userRepository Repositorio para acceder a los datos de los usuarios.
     */
    public AppConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Define un bean para el servicio de detalles de usuario.
     * Este servicio se utiliza para cargar los detalles del usuario durante la autenticación.
     *
     * @return UserDetailsService que carga los detalles del usuario basado en el email.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            // Busca el usuario por su email (username)
            final User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Construye un UserDetails con el email y la contraseña del usuario
            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getEmail())
                    .password(user.getPassword())
                    .build();
        };
    }

    /**
     * Define un bean para el proveedor de autenticación.
     * Este proveedor utiliza el UserDetailsService y un codificador de contraseñas para autenticar a los usuarios.
     *
     * @return AuthenticationProvider configurado con UserDetailsService y PasswordEncoder.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService()); // Configura el UserDetailsService
        authenticationProvider.setPasswordEncoder(passwordEncoder()); // Configura el PasswordEncoder
        return authenticationProvider;
    }

    /**
     * Define un bean para el administrador de autenticación.
     * Este bean se utiliza para gestionar el proceso de autenticación.
     *
     * @param config Configuración de autenticación proporcionada por Spring Security.
     * @return AuthenticationManager que gestiona la autenticación.
     * @throws Exception Si ocurre un error al obtener el AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Define un bean para el codificador de contraseñas.
     * Este codificador se utiliza para encriptar y verificar las contraseñas de los usuarios.
     *
     * @return PasswordEncoder que utiliza el algoritmo BCrypt.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}