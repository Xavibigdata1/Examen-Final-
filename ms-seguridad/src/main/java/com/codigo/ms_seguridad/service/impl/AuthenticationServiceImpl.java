package com.codigo.ms_seguridad.service.impl;

import com.codigo.ms_seguridad.aggregates.constants.Constants;
import com.codigo.ms_seguridad.aggregates.request.SignInRefreshToken;
import com.codigo.ms_seguridad.aggregates.request.SignInRequest;
import com.codigo.ms_seguridad.aggregates.request.SignUpRequest;
import com.codigo.ms_seguridad.aggregates.response.SignInResponse;
import com.codigo.ms_seguridad.entity.Rol;
import com.codigo.ms_seguridad.entity.Role;
import com.codigo.ms_seguridad.entity.Usuario;
import com.codigo.ms_seguridad.repository.RolRepository;
import com.codigo.ms_seguridad.repository.UsuarioRepository;
import com.codigo.ms_seguridad.service.AuthenticationService;
import com.codigo.ms_seguridad.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Override
    public Usuario signUpUser(SignUpRequest signUpRequest) {
        Usuario usuario=getUsuarioEntity(signUpRequest);
        usuario.setRoles(Collections.singleton(getRoles(Role.USER)));

        return usuarioRepository.save(usuario);
    }
    private Usuario getUsuarioEntity(SignUpRequest signUpRequest){
              return   Usuario.builder()
                      .nombres(signUpRequest.getNombres())
                      .apellidos(signUpRequest.getApellidos())
                      .email(signUpRequest.getEmail())
                      .password(new BCryptPasswordEncoder().encode(signUpRequest.getPassword()))
                      .tipoDoc(signUpRequest.getTipoDoc())
                      .numDoc(signUpRequest.getNumDoc())
                      .isAccountNonExpired(Constants.STATUS_ACTIVE)
                      .isAccountNonLocked(Constants.STATUS_ACTIVE)
                      .isCredentialsNonExpired(Constants.STATUS_ACTIVE)
                      .isEnabled(Constants.STATUS_ACTIVE)
                      .build();
    }

    @Override
    public Usuario signUpAdmin(SignUpRequest signUpRequest) {
        Usuario usuario=getUsuarioEntity(signUpRequest);

        Set<Rol> roles=new HashSet<>();
        roles.add(getRoles(Role.USER));
        roles.add(getRoles(Role.ADMIN));
        usuario.setRoles(roles);
        //usuario.setRoles(Collections.singleton(getRoles(Role.ADMIN)));
        return usuarioRepository.save(usuario);
    }


    @Override
    public List<Usuario> todos() {
        return usuarioRepository.findAll();
    }

    @Override
    public SignInResponse singIn(SignInRequest signInRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                signInRequest.getEmail(),signInRequest.getPassword()
        ));
        var user = usuarioRepository.findByEmail(signInRequest.getEmail()).orElseThrow(
                ()->new UsernameNotFoundException("Error usuario no encontrado en la base de datos  "));
        var token= jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(new HashMap<>(),user);
        return SignInResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public SignInResponse getTokenByRefresh(SignInRefreshToken signInRefreshToken) {
        //validamos que sea un refresh token
        if(!jwtService.isRefreshToken(signInRefreshToken.getRefreshToken())){
            throw new RuntimeException("ERROR EL TOKEN INGRESADO NO ES: TYPE: REFRESH");
        }

        //ESTRAEMOS EL SUBOBJECT DEL TOKEN
        String userEmail=jwtService.extractUsername(signInRefreshToken.getRefreshToken());
        //BUSCAMOS A L SUJETO EN AL BASE DE DATOS
        Usuario usuario=usuarioRepository.findByEmail(userEmail).orElseThrow(
                ()->new UsernameNotFoundException("no se encontro el usuario"));
        //validamos que el refresh le pertenezca al usuario
        if(!jwtService.validateToken(signInRefreshToken.getRefreshToken(),usuario)){
            throw new RuntimeException("Error el token no le pertenece al usuario");
        }
        //Generamos el nuevo token access
        String newToken=jwtService.generateToken(usuario);
        //si gustamos podemos un nuevo refresh token,
        //caso contrario devolvemos  el mismocon el que generamos
        return SignInResponse.builder()
                .token(newToken)
                .refreshToken(signInRefreshToken.getRefreshToken())
                .build();
    }

    private Rol getRoles(Role rolbuscado){
    return rolRepository.findByNombreRol(rolbuscado.name())
            .orElseThrow(()->new RuntimeException("ERROR EL ROL  NO EXISTE :  "+rolbuscado.name()));
    }
}
