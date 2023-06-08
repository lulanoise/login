package com.develhope.login.auth.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.develhope.login.auth.entities.LoginDTO;
import com.develhope.login.auth.entities.LoginRTO;
import com.develhope.login.users.entities.User;
import com.develhope.login.users.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Service
public class LoginService {

    public static final String JWT_SECRET = "49bb2c8c-494f-4a79-a6b5-bbae1a3965bd";

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public LoginRTO login (LoginDTO loginDTO) {

        if (loginDTO == null) return null;
        User userFromDB =  userRepository.findByEmail(loginDTO.getEmail());
        if (userFromDB == null || !userFromDB.isActive()) return null;
        boolean canLogin = this.canUserLogin(userFromDB, loginDTO.getPassword());
        if (!canLogin) return null;

        String JWT = getJWT(userFromDB);

        userFromDB.setJwtCreatedOn(LocalDateTime.now());
        userRepository.save(userFromDB);

        userFromDB.setPassword(null);
        LoginRTO out = new LoginRTO();
        out.setJWT(JWT);
        out.setUser(userFromDB);

        return out;
    }

    public boolean canUserLogin(User user, String password){
        return passwordEncoder.matches(password, user.getPassword());

    }

    public static Date convertToDateViaInstant(LocalDateTime dateToConvert){
        return java.util.Date.from(dateToConvert.atZone(ZoneId.systemDefault()).toInstant());
    }

    //https://www.uuidgenerator.net
    public static String getJWT(User user){
        Date expiresAt = convertToDateViaInstant(LocalDateTime.now().plusDays(15));
        return JWT.create()
                .withIssuer("develhope-demo")
                .withIssuedAt(new Date ())
                .withExpiresAt(expiresAt)
                .withClaim("id", user.getId())
                .sign(Algorithm.HMAC512(JWT_SECRET));
    }

    public String generateJWT(User user){
        String JWT = getJWT(user);
        user.setJwtCreatedOn(LocalDateTime.now());
        userRepository.save(user);
        return JWT;
    }
}
