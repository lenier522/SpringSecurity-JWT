package org.example.springsecurityjwt.controller;

public record RegisterRequest(
        String email,
        String password,
        String name
){

}
