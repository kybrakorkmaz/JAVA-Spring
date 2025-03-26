package com.korkmaz.kubra.auth.repositories;

import com.korkmaz.kubra.auth.entity.ActiveToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ActiveTokenRepository extends JpaRepository<ActiveToken, Integer> {

    Optional<ActiveToken>findByActiveToken(String activeToken);
}
