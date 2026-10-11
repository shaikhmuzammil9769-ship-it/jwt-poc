package com.demo.jwtpoc.services;

import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.demo.jwtpoc.entities.User;
import com.demo.jwtpoc.repositories.UserRepository;

@Service
public class AuthService {

	private final UserRepository userRepository;

	private final PasswordEncoder passwordEncoder;
	
	private final JwtService jwtService;

	public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;

	}

	public String register(User user) {

		if (userRepository.findByUsername(user.getUsername()).isPresent()) {

			return "User already existing";

		}

		// Hash the plain-text password using BCrypt

		String encodedPassword = passwordEncoder.encode(user.getPassword());

		// Set the BCrypt hash instead of the plain-text password
		user.setPassword(encodedPassword);

		userRepository.save(user);

		return "User registered successfully";
	}




public String Login(String username, String password) {
	
	
	Optional<User> optionalUser = userRepository.findByUsername(username);
	
			  if (optionalUser.isEmpty()) {
			        return "User not found";
			    }
			
	 User user = optionalUser.get();
			
	 if (passwordEncoder.matches(password, user.getPassword())) {

		    // Generate JWT token after successful password verification
		    String token = jwtService.generateToken(user.getUsername());

		    // Return the generated JWT token
		    return token;
		}
	
	return "Invalid Password";
	
	
	
	
}


}




