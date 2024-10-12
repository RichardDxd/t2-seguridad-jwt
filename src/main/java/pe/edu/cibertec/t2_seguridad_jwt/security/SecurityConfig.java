package pe.edu.cibertec.t2_seguridad_jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pe.edu.cibertec.t2_seguridad_jwt.service.UsuarioService;

@Configuration
public class SecurityConfig {

    private final JwtService jwtService;
    private final UsuarioService usuarioService;

    public SecurityConfig(JwtService jwtService, UsuarioService usuarioService) {
        this.jwtService = jwtService;
        this.usuarioService = usuarioService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()  // Deshabilitamos CSRF
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/gestor").hasRole("GESTOR")  // Para el acceso solo a Gestores
                        .requestMatchers("/api/coordinador").hasRole("COORDINADOR")  // Para el acceso solo a Coordinadores
                        .requestMatchers("/api/actualizar").hasAnyRole("GESTOR", "COORDINADOR")  // Para Gestores y Coordinadores
                        .anyRequest().authenticated()  // Resto de las rutas requieren autenticación
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtService, usuarioService), UsernamePasswordAuthenticationFilter.class);  // Añadimos filtro JWT
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
