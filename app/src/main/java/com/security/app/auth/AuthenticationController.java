package com.security.app.auth;

import com.security.app.service.AuthenticationService;
import com.security.app.vos.AuthenticateRequest;
import com.security.app.vos.AuthenticationResponse;
import com.security.app.vos.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
  private final AuthenticationService service;

  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest body) {
    return ResponseEntity.ok(service.register(body));
  }

  @PostMapping("/authentication")
  public ResponseEntity<AuthenticationResponse> authentication(
      @RequestBody AuthenticateRequest body) {
    return ResponseEntity.ok(service.authenticate(body));
  }
}
