package pe.edu.cibertec.t2_seguridad_jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pe.edu.cibertec.t2_seguridad_jwt.model.Usuario;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByCodigo(String codigo);
    Optional<Usuario> findByEmail(String email);
}
