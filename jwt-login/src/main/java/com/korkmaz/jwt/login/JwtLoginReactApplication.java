package com.korkmaz.jwt.login;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
public class JwtLoginReactApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtLoginReactApplication.class, args);
	}

}
