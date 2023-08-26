package io.phamust.securityjwt.security.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain) throws ServletException, IOException {

        //Jwt authentication token is in the header -- We want to extract it
        // Authorization is the header name
        final String authHeader = request.getHeader("Authorization");

        final String jwt;
        final String userEmail;

        //Bearer token should always start with Bearer keyword
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        //Token is just after Bearer + " " (7)
        jwt = authHeader.substring(7);

        //Extracting the username from the token
        userEmail = jwtService.extractUsername(jwt);
        //Checking if the username isn't null and there is no authentication yet
        if (userEmail!=null && SecurityContextHolder.getContext().getAuthentication() == null){
            //We get the user details from db
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt,userDetails)){
                // Needed by spring security context holder in order to update the context
                UsernamePasswordAuthenticationToken authenticationToken =
                        //Presentation of a username and password
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                //Building details on token out of the HTTP request
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //Updating the context with authToken
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            //Passing the hand to the next filter to be executed
            filterChain.doFilter(request,response);
        }

    }
}
