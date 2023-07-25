package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;


@Component
public class JwtProvider {

    /*
        In this class:
            1. Method to generate Token
            2. Method to validate token
            3. Method to parse token(extract username from token)
     */

    //sectret key to create token
    private String secretKey = "sboot";

    //token expiration duration
    private long jwtExpiration = 86400000; //24hours*60min*60seconds*1000 = 24 hours


    //++++++++++Method to Generate token+++++++++++

    /*

    Token should be generated for authenticated / signed user

        To generate/build token we need 3 things:
            1. userName of authenticated user
            2. expire time
            3. secret key
     */

    public String createToken(Authentication authentication){

        //we are getting user info of currently logged in user
        UserDetailsImpl authenticatedUser = (UserDetailsImpl) authentication.getPrincipal(); //getPrinciple() returns
        // authenticated suer

        return Jwts.builder().
                setSubject(authenticatedUser.getUsername()). //set userName of logged in user
                        setIssuedAt(new Date()).                  //the time when token created
                        setExpiration(new Date(new Date().getTime()+jwtExpiration)). //time when token will be expired
                        signWith(SignatureAlgorithm.HS512, secretKey). //encoding method/algorithm with secret key
                        compact(); //compact //compress //zip

    }


    //++++++++++Method to Validate token+++++++++++

    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token); //validating token
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;

    }


    //++++++++++Method to Parse token+++++++++++
    //to extract userName from token
    public String getUserNameFromToken(String token){
        return Jwts.parser().setSigningKey(secretKey).
                parseClaimsJws(token).
                getBody(). //reach out token body
                        getSubject(); //we used setSubject method to create token, now we are using getSubject method
    }




}