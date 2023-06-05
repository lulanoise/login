package com.develhope.login.auth.controller;

import com.develhope.login.auth.entities.SignUpActivationDTO;
import com.develhope.login.auth.entities.SignUpDTO;
import com.develhope.login.auth.services.SignUpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class SignUpController {

    @Autowired
    private SignUpService signUpService;

    @PostMapping("/signup")
    public void signup(@RequestBody SignUpDTO signUpDTO) throws Exception {
        signUpService.signUp(signUpDTO);
    }

    @PostMapping("/signup/activation")
    public void signup (@RequestBody SignUpActivationDTO signUpActivationDTO) throws Exception {
        signUpService.activate(signUpActivationDTO);
    }

}
