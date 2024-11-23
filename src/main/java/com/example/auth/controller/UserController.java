package com.example.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.auth.entity.UserEntity;
import com.example.auth.model.JwtTokenModel;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtToken;
import com.example.auth.service.impl.LoginServiceImpl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/")
public class UserController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	private JwtToken jwtToken;

	@Autowired
	private LoginServiceImpl loginServiceImpl;

	@PostMapping("register")
	public ResponseEntity<?> register(@RequestBody UserEntity userEntity) {
		userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
		UserEntity savedEntity = userRepository.save(userEntity);
		return new ResponseEntity<>(savedEntity, HttpStatus.CREATED);
	}

	@PostMapping("login")
	public ResponseEntity<?> login(@RequestBody UserEntity userEntity, HttpServletRequest request,
			HttpServletResponse response) {
		try {
			String login = loginServiceImpl.login(userEntity, request, response);
			if (login != null) {
				String token = jwtToken.generateToken(userEntity.getEmail());
				JwtTokenModel jwtModel = new JwtTokenModel(token);
				return new ResponseEntity<>(jwtModel, HttpStatus.OK);
			} else {
				return new ResponseEntity<>("Login Unsuccessful", HttpStatus.UNAUTHORIZED);
			}
		} catch (Exception ex) {
			return new ResponseEntity<>("Login Unsuccessful: " + ex.getMessage(), HttpStatus.UNAUTHORIZED);
		}
	}
	
	@GetMapping("get-message-everyone")
	public ResponseEntity<?> getMessageForEveryone(){
		return new ResponseEntity<>("Hello Everyone",HttpStatus.OK);
	}
	
	@GetMapping("get-message")
	public ResponseEntity<?> getMessage(){
		return new ResponseEntity<>("Hello, Admin",HttpStatus.OK);
	}
}
