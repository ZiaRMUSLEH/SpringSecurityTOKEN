package com.tpe.service;

import com.tpe.domain.Role;
import com.tpe.domain.User;
import com.tpe.domain.enums.UserRole;
import com.tpe.dto.RegisterRequest;
import com.tpe.exception.ConflictException;
import com.tpe.exception.ResourceNotFoundException;
import com.tpe.repository.RoleRepository;
import com.tpe.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepository roleRepository; //this is not good practice,
    // service class should talk to service class and service should talk its own repo class

    public void registerUser(RegisterRequest request) {
        // check if username is unique
        if(userRepository.existsByUserName(request.getUserName())){
            throw  new ConflictException("Username is already in DB");
        }

        //to assign default role to user,
        Role role = roleRepository.findByName(UserRole.ROLE_STUDENT).orElseThrow(
                ()->new ResourceNotFoundException("Role not found")
        );

        Set<Role> roles =new HashSet<>();
        roles.add(role);

        //to map dto to User
        User newUser = new User();
        newUser.setFirstName(request.getFirstName());
        newUser.setLastName(request.getLastName());
        newUser.setUserName(request.getUserName());
        newUser.setRoles(roles);
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));


        userRepository.save(newUser);

    }
}