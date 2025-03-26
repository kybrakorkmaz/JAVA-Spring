package com.korkmaz.security;

import com.korkmaz.security.auth.AuthenticationService;
import com.korkmaz.security.auth.RegisterRequest;
import com.korkmaz.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import static com.korkmaz.security.user.Role.ADMIN;
import static com.korkmaz.security.user.Role.MANAGER;

@SpringBootApplication
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authenticationService) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstname("admin")
					.lastname("admin")
					.email("admin@admin.com")
					.password("password")
					.role(ADMIN)
					.build();
			System.out.println("admin token: " + authenticationService.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.firstname("manager")
					.lastname("manager")
					.email("manager@manager.com")
					.password("password")
					.role(MANAGER)
					.build();
			System.out.println("manager token: " + authenticationService.register(manager).getAccessToken());
		};
	}

}
