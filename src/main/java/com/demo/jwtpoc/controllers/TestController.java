package com.demo.jwtpoc.controllers;

import com.demo.jwtpoc.services.JwtService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class TestController {

    private final JwtService jwtService;

    public TestController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    // Test 1: Generate a token for a username
    @GetMapping("/generate")
    public String generate(@RequestParam String username) {     
    	
    	
        return jwtService.generateToken(username);
    }

    // Test 2: Validate a token against an expected username
    @GetMapping("/validate")
    public String validate(@RequestParam String token,
                           @RequestParam String username) {
        return jwtService.validateToken(token, username);
    }
}