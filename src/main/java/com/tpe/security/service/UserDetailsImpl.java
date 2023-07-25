package com.tpe.security.service;

import com.tpe.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor

public class UserDetailsImpl implements UserDetails {

    //convert user to userDetail
    private Long id;
    private String userName;
    private String password;

    private Collection<? extends GrantedAuthority> authority;

    //method to return userDetail from normal user

    //using lambda we have converted role to role of SimpleGrantedAuthority
    //and collecting stream result into list
    public static  UserDetailsImpl build(User user){
        List<SimpleGrantedAuthority> authorities = user.getRoles().stream().
                map(role -> new SimpleGrantedAuthority(role.getName().name())).
                collect(Collectors.toList());



        //we have @AllArgsConstructor
        return new UserDetailsImpl(user.getId(), user.getUserName(), user.getPassword(), authorities);
    }


    //any data type which extends from GrantedAuthority
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authority;
    }



    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}