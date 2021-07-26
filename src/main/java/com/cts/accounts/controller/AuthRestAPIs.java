package com.cts.accounts.controller;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cts.accounts.message.request.LoginForm;
import com.cts.accounts.message.response.JwtResponse;
import com.cts.accounts.message.response.ResponseMessage;
import com.cts.accounts.model.Role;
import com.cts.accounts.model.RoleName;
import com.cts.accounts.model.User;
import com.cts.accounts.repository.RoleRepository;
import com.cts.accounts.repository.UserRepository;
import com.cts.accounts.security.jwt.JwtProvider;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtProvider jwtProvider;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtProvider.generateJwtToken(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), userDetails.getAuthorities()));
	}

	@PostMapping("/insert")
	public ResponseEntity<?> registerUser(@Valid @RequestBody User user) {
		

		// Creating user's account
		User user1 = new User(user.getFirstname(), user.getLastname(), 
								user.getUsername(), user.getEmail(),
				encoder.encode(user.getPassword()));

		
		userRepository.save(user1);
		

		return new ResponseEntity<>(new ResponseMessage("User "+ user.getFirstname() + " is inserted  successfully!"), HttpStatus.OK);
	}
}