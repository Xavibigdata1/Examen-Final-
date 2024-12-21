package com.codigo.ms_seguridad.service;

import com.codigo.ms_seguridad.aggregates.request.SignInRefreshToken;
import com.codigo.ms_seguridad.aggregates.request.SignInRequest;
import com.codigo.ms_seguridad.aggregates.request.SignUpRequest;
import com.codigo.ms_seguridad.aggregates.response.SignInResponse;
import com.codigo.ms_seguridad.entity.Usuario;

import java.util.List;

public interface AuthenticationService {

    //signup -->registrarse

    Usuario signUpUser(SignUpRequest signUpRequest);
    Usuario signUpAdmin(SignUpRequest signUpRequest);
    List<Usuario>todos();
    //metodos de autenticacion
    SignInResponse  singIn(SignInRequest signInRequest);
    // obtener nuevo token desde un refresh token
    SignInResponse getTokenByRefresh(SignInRefreshToken signInRefreshToken);




}
