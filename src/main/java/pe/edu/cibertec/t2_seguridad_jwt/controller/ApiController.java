package pe.edu.cibertec.t2_seguridad_jwt.controller;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ApiController {
    @PostMapping("/gestor")
    @PreAuthorize("hasRole('GESTOR')")
    public HttpStatus crear(@RequestBody String data) {
        // Lógica para crear algo solo accesible por Gestores
        return HttpStatus.CREATED;
    }

    @GetMapping("/coordinador")
    @PreAuthorize("hasRole('COORDINADOR')")
    public String obtenerDatos() {
        // Lógica para obtener datos solo accesibles por Coordinadores
        return "Datos solo para Coordinador";
    }

    @PutMapping("/actualizar")
    @PreAuthorize("hasRole('GESTOR') or hasRole('COORDINADOR')")
    public HttpStatus actualizar(@RequestBody String data) {
        // Lógica para actualizar datos accesibles por Gestores y Coordinadores
        return HttpStatus.OK;
    }
}
