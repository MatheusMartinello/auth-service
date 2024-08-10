package com.security.app.service;

import com.security.app.config.JwtService;
import com.security.app.user.User;
import com.security.app.user.UserRepository;
import com.security.app.vos.AuthenticateRequest;
import com.security.app.vos.AuthenticationResponse;
import com.security.app.vos.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;

  private final PasswordEncoder encoder;

  private final JwtService jwtService;
  private final AuthenticationManager manager;

  public final AuthenticationResponse register(RegisterRequest body) {
    var user =
        User.builder()
            .firstName(body.getFirstName())
            .lastName(body.getLastName())
            .email(body.getEmail())
            .password(encoder.encode(body.getPassword()))
            .build();
    repository.save(user);
    final String token = jwtService.generateToken(user);

    return AuthenticationResponse.builder().token(token).build();
  }

  public AuthenticationResponse authenticate(AuthenticateRequest body) {
    manager.authenticate(
        new UsernamePasswordAuthenticationToken(body.getEmail(), body.getPassword()));
    var user = repository.findByEmail(body.getEmail()).orElseThrow();
    final String token = jwtService.generateToken(user);
    return AuthenticationResponse.builder().token(token).build();
  }
}
