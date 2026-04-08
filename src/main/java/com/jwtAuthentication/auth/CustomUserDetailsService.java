package com.jwtAuthentication.auth;

import com.jwtAuthentication.auth.refreshToken.CustomeUserDetails;
import com.jwtAuthentication.user.UserEntity;
import com.jwtAuthentication.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepo;

    @Override
    public CustomeUserDetails loadUserByUsername(String username) {

        UserEntity user = userRepo.findByUsername(username);

        return new CustomeUserDetails(
                user.getUserId(),
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                List.of(new SimpleGrantedAuthority(user.getUserRole()))

        );
    }


}
