package com.korkmaz.kubra.auth.repositories;

import com.korkmaz.kubra.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    //SDP
    Optional<User> findByEmail(String email);

}
