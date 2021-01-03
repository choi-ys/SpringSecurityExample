package io.example.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/custom_login")
    public String loginPage(){
        return "/loginPage";
    }
}
