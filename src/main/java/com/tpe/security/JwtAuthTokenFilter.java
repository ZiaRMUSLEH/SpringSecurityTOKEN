package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthTokenFilter extends OncePerRequestFilter {

    /*
        This class is filter. In this class,
         need to extract token from header
         we will validate user credentials

     */

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, //we can reach request info
                                    HttpServletResponse response, //we can reach response info
                                    FilterChain filterChain)
            throws ServletException, IOException {

        //call method to extract token from header
        String token= parseJwt(request);

        //check if the token is valid?
        try {
            if(token!=null && jwtProvider.validateToken(token)){

                String userName = jwtProvider.getUserNameFromToken(token); //extract userFrom Token
                UserDetails authenticatedUser = userDetailsService.loadUserByUsername(userName); //by passing userName,
                // we can get UserDetails user (an user recognized by security)


                //we need to authenticate one more time, and place/ populate it into security context holder

                //
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        authenticatedUser, //user itself
                        null, //if wee to place extra data about user we need to write here
                        authenticatedUser.getAuthorities() //role of user
                );

                SecurityContextHolder.getContext().setAuthentication(authentication); //placing authenticated user
                // in security context holder

            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }


        //requests and response should be filtered
        filterChain.doFilter(request, response);

    }

    //method to return token from header
    private String parseJwt(HttpServletRequest request){

        //Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJDaWdkZW0iLCJpYXQiOjE2ODQzNzUwNDksImV4cCI6MTY4NDQ2MTQ0OX0.azoHaAaBWnKMiInTMVyVbMPbFJfztjw7ay3fJR13sC59p2Z9qq7ljzdWc9iRylMyvFbdu8QyQXb69fRw3Jn4sg

        String header = request.getHeader("Authorization"); // using request from header we need to get value of Authorization
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")){
            return header.substring(7);
        }
        return null;
    }


    //shouldNotFilter is used to specify that specific filter should not be applied to particular request,
    //bypass the execution of the filter for matching request
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        return antPathMatcher.match("/register", request.getServletPath()) ||
                antPathMatcher.match("/login", request.getServletPath());
    }
}