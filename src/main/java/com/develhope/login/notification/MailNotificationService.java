package com.develhope.login.notification;

import com.develhope.login.users.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailNotificationService {

    @Autowired
    JavaMailSender emailSender;

    public void sendActivationEmail(User user) {
        SimpleMailMessage sms = new SimpleMailMessage();
        sms.setTo(user.getEmail());
        sms.setFrom("lucrezia@develhope.ciao");
        sms.setReplyTo("lucrezia@develhope.ciao");
        sms.setSubject("Ti sei iscritto alla piattaforma");
        sms.setText("Il codice di attivazione è: " + user.getActivationCode());
        emailSender.send(sms);
    }

    public void sendPasswordResetMail(User user) {
        SimpleMailMessage sms = new SimpleMailMessage();
        sms.setTo(user.getEmail());
        sms.setFrom("lucrezia@develhope.ciao");
        sms.setReplyTo("lucrezia@develhope.ciao");
        sms.setSubject("Ti sei iscritto alla piattaforma");
        sms.setText("Il codice di attivazione è: " + user.getPasswordResetCode());
        emailSender.send(sms);
    }
}
