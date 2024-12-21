package com.codigo.ms_seguridad.controller;

import com.codigo.ms_seguridad.entity.Usuario;
import com.codigo.ms_seguridad.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/user/v1/")
@RequiredArgsConstructor
public class UserController {

    private final UsuarioService usuarioService;

    @RequestMapping("/saludo")
    public ResponseEntity<String> getsaludo(){
        return ResponseEntity.ok("Hola User");
    }

    @GetMapping("/all")
    public ResponseEntity<List<Usuario>> getInfo(){
        return ResponseEntity.ok(usuarioService.getInfoUser());
    }
}
