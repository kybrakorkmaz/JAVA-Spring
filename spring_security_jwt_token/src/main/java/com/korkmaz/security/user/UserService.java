package com.korkmaz.security.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {

        var user = ((User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal());
        //check if the current password is correct
        if(!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())){
            throw new IllegalArgumentException("Wrong password");
        }
        //check if the two new passwords are the same
        if(!request.getNewPassword().equals(request.getConfirmPassword())){
            throw new IllegalArgumentException("Password are not the same");
        }
        //update the password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        //save the new password
        userRepository.save(user);
    }
}
