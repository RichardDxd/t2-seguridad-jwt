package pe.edu.cibertec.t2_seguridad_jwt.security;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pe.edu.cibertec.t2_seguridad_jwt.service.UsuarioService;

import java.io.IOException;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtService jwtService;
    private final UsuarioService usuarioService;

    public JwtAuthenticationFilter(JwtService jwtService, UsuarioService usuarioService) {
        this.jwtService = jwtService;
        this.usuarioService = usuarioService;
    }


    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // Obtener el token JWT del encabezado Authorization
        String token = request.getHeader("Authorization");

        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);  // Eliminar el prefijo "Bearer"
            try {
                // Extraer el usuario del token
                String username = jwtService.extraerUsuario(token);  // Cambié extractUsername a extraerUsuario

                // Verificar que el usuario no esté autenticado previamente
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    // Cargar los detalles del usuario desde la base de datos
                    UserDetails userDetails = usuarioService.loadUserByUsername(username);

                    // Validar el token JWT
                    if (jwtService.validarToken(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                        // Establecer detalles de autenticación
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        // Establecer el usuario autenticado en el contexto de seguridad
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            } catch (ExpiredJwtException e) {
                System.out.println("Token JWT expirado: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("Error en la autenticación con JWT: " + e.getMessage());
            }
        }

        // Continuar con el resto de la cadena de filtros
        chain.doFilter(request, response);
    }
}
