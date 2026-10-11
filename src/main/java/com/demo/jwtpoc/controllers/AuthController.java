package com.demo.jwtpoc.controllers;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.demo.jwtpoc.dto.LoginRequest;
import com.demo.jwtpoc.entities.User;
import com.demo.jwtpoc.services.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {
	
	  private  AuthService authService;
	  
	  
	  
	  public AuthController( AuthService authService) {
		  
		  this.authService=authService;
		  
	  }
	  
	  @PostMapping("/register")
	  public String register(@RequestBody User user) {
		return authService.register(user);
		  
		  
		  
	  }
	  
	  @PostMapping("/login")
	  public String login(@RequestBody LoginRequest request) {
		return authService.Login(request.getUsername(), request.getPassword());
		  
		  
		  
	  }
	  
}
