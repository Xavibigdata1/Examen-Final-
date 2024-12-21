package com.codigo.ms_seguridad.config;

import com.codigo.ms_seguridad.service.JwtService;
import com.codigo.ms_seguridad.service.UsuarioService;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UsuarioService usuarioService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String tokenExtraidoHeader=request.getHeader("Authorization");
        final String tokenlimpio;
        final String useremail;

        //Validar el encabezado de la solicitud, validamos el token
        if(StringUtils.isEmpty(tokenExtraidoHeader)
            || !org.springframework.util.StringUtils.startsWithIgnoreCase (tokenExtraidoHeader, "Bearer ")){
                filterChain.doFilter(request, response);
                return;
        }
        //Limpiamos el token de la palabra Bearer
        tokenlimpio = tokenExtraidoHeader.substring(7);
        //extraemos el usuario(username) del token
        useremail=jwtService.extractUsername(tokenlimpio);
        //Validamnos si el usuario no es nulo y no se encuentre autenticado
        if(Objects.nonNull(useremail)&&
                SecurityContextHolder.getContext().getAuthentication()==null){
            //definiendo un contexto de seguridad vacio(empety)
            SecurityContext securityContext=SecurityContextHolder.createEmptyContext();
            //Recuperando los detalles del usuario desde base de datos
            UserDetails userDetails=usuarioService.userDetailsService().loadUserByUsername(useremail);
            //validamos el token(que no este expirado y que pertenezca al usuario)
            if(jwtService.validateToken(tokenlimpio,userDetails)&&
            !jwtService.isRefreshToken(tokenlimpio)){
                //Creamos un token de authenticacion a travez de usernamepasswordAuthenticationtoken(aqui
                // requerimos de colocar los detalles del usuario,credenciales, roles/permisos)
                UsernamePasswordAuthenticationToken authenticationToken=
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                //estoy asignando los detalles de la solicitud osea del request a mi token de autenticaciòn
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //Asignando la autenthicaciòn a mi contexto creado anteriormente
                securityContext.setAuthentication(authenticationToken);
                // asigno mi contexto de seguridad  al holder de Securidad
                SecurityContextHolder.setContext(securityContext);
            }
        }
        //todo ok, continua con al ejecución de la solicitud
        filterChain.doFilter(request,response);
    }
}
