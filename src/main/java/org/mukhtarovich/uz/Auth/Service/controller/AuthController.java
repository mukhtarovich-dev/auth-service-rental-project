package org.mukhtarovich.uz.Auth.Service.controller;

import lombok.RequiredArgsConstructor;
import org.mukhtarovich.uz.Auth.Service.dto.ApiResponse;
import org.mukhtarovich.uz.Auth.Service.dto.AuthRequest;
import org.mukhtarovich.uz.Auth.Service.dto.AuthResponse;
import org.mukhtarovich.uz.Auth.Service.dto.RefreshTokenRequest;
import org.mukhtarovich.uz.Auth.Service.service.AuthService;
import org.mukhtarovich.uz.Auth.Service.service.JwtService;
import org.mukhtarovich.uz.Auth.Service.service.TelegramOtpService;
import org.mukhtarovich.uz.Auth.Service.service.TempSessionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
     private final AuthenticationManager authenticationManager;
     private final TempSessionService tempSessionService;
     private final TelegramOtpService telegramOtpService;
     private final JwtService jwtService;
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> auth(@RequestBody AuthRequest authRequest) {

        try {

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getPhoneNumber(),
                            authRequest.getPassword()));

            UserDetails user = (UserDetails) authentication.getPrincipal();

            // temp token
            String tempToken = UUID.randomUUID().toString();

            tempSessionService.save(tempToken, user.getUsername());

            // OTP yuborish
            telegramOtpService.sendOtp(user.getUsername());

            return ResponseEntity.ok(
                    new ApiResponse<>("OTP sent", HttpStatus.OK, true, tempToken));

        } catch (Exception e) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid username or password",
                            HttpStatus.UNAUTHORIZED, false, null));
        }
    }
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody RefreshTokenRequest request) {

        String username = jwtService.extractUsername(request.getToken());
        UserDetails user = authService.loadUserByUsername(username);
        if(jwtService.isTokenExpired(request.getToken())) {

            String newAccessToken = jwtService.generateAccessToken(user);

            return ResponseEntity.ok(
                    new AuthResponse(newAccessToken, request.getToken())
            );
        }

        throw new RuntimeException("Invalid refresh token");
    }
}
