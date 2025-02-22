package org.example.springsecurityjwt.controller;

public record LoginRequest(
        String email,
        String password
) {
}
