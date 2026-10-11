package com.demo.jwtpoc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;


@SpringBootApplication
public class JwtPocApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtPocApplication.class, args);
    }
}