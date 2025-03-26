package com.korkmaz.security.user;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService service;
    @PatchMapping(params = "/{id}", consumes = "application/json")
    public ResponseEntity <?> changePassword(
            @RequestBody ChangePasswordRequest request,
            Principal connectedUser
    ){
        try {
            service.changePassword(request, connectedUser);
            return ResponseEntity.accepted().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error: " + e.getMessage());
        }
    }

}
