package com.develhope.login.auth.services;

import com.develhope.login.auth.entities.RequestPasswordDTO;
import com.develhope.login.auth.entities.RestorePasswordDTO;
import com.develhope.login.notification.MailNotificationService;
import com.develhope.login.users.entities.User;
import com.develhope.login.users.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.management.Notification;
import java.util.UUID;

@Service
public class PasswordService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MailNotificationService mailNotificationService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    public void request(@RequestBody RequestPasswordDTO requestPasswordDTO) throws Exception {
       User userFromDB = userRepository.findByEmail(requestPasswordDTO.getEmail());
       if (userFromDB == null) throw new Exception("Cannot find user");
       userFromDB.setPasswordResetCode(UUID.randomUUID().toString());
       mailNotificationService.sendPasswordResetMail(userFromDB);
       userRepository.save(userFromDB);

    }

    public User restore(@RequestBody RestorePasswordDTO restorePasswordDTO) throws Exception{
        User userFromDB = userRepository.findByPasswordResetCode(restorePasswordDTO.getResetPasswordCode());
        if (userFromDB == null) throw new Exception("user is null");
        userFromDB.setPassword(passwordEncoder.encode(restorePasswordDTO.getNewPassword()));
        userFromDB.setPasswordResetCode(null);

        userFromDB.setActive(true);
        userFromDB.setActivationCode(null);
        return userRepository.save(userFromDB);
    }


}
