package pe.edu.cibertec.t2_seguridad_jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime; // Expiración en milisegundos (por ejemplo, 180000 para 3 minutos)

    // Generar token JWT
    public String generarToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())  // El sujeto del token será el nombre de usuario
                .setIssuedAt(new Date())  // Fecha de emisión
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))  // Expiración
                .signWith(SignatureAlgorithm.HS256, secretKey)  // Firma usando HS256 y la clave secreta
                .compact();
    }

    // Validar el token JWT
    public boolean validarToken(String token, UserDetails userDetails) {
        final String username = extraerUsuario(token);
        return (username.equals(userDetails.getUsername()) && !esTokenExpirado(token));
    }

    public String extraerUsuario(String token) {
        return obtenerClaims(token).getSubject();
    }

    // Verificar si el token ha expirado
    public boolean esTokenExpirado(String token) {
        return obtenerClaims(token).getExpiration().before(new Date());
    }

    private Claims obtenerClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }
}
