package pe.edu.cibertec.t2_seguridad_jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import pe.edu.cibertec.t2_seguridad_jwt.model.Usuario;
import pe.edu.cibertec.t2_seguridad_jwt.repository.UsuarioRepository;

import java.util.Optional;

@Service
public class UsuarioService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    @Autowired
    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Buscamos al usuario por su código (username)
        Optional<Usuario> optionalUsuario = usuarioRepository.findByCodigo(username);

        // Si el usuario no está presente, lanzamos una excepción
        Usuario usuario = optionalUsuario.orElseThrow(() ->
                new UsernameNotFoundException("Usuario no encontrado con código: " + username)
        );

        // Retornamos los detalles del usuario, construidos con su username, password y roles
        return org.springframework.security.core.userdetails.User.builder()
                .username(usuario.getCodigo())
                .password(usuario.getPassword())  // Asegúrate de que la contraseña esté cifrada con BCrypt
                .roles("ROLE_" + usuario.getRol())  // Spring Security espera que los roles tengan el prefijo "ROLE_"
                .build();
    }

    // Método para encriptar la contraseña al registrar un nuevo usuario
    public void registrarUsuario(Usuario usuario) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));  // Encriptamos la contraseña
        usuarioRepository.save(usuario);  // Guardamos el usuario en la base de datos
    }
}
