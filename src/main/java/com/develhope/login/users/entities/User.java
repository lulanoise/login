package com.develhope.login.users.entities;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String surname;
    @Column(unique = true)
    private String email;
    private String password;
    private boolean isActive;
    private LocalDateTime jwtCreatedOn; //jwt.io
    @Column(length = 36)
    private String activationCode;
    @Column(length = 36)
    private String PasswordResetCode;

    public User(Long id, String name, String surname, String email, String password, boolean isActive, LocalDateTime jwtCreatedOn, String activationCode, String passwordResetCode) {
        this.id = id;
        this.name = name;
        this.surname = surname;
        this.email = email;
        this.password = password;
        this.isActive = isActive;
        this.jwtCreatedOn = jwtCreatedOn;
        this.activationCode = activationCode;
        PasswordResetCode = passwordResetCode;
    }

    public User (){}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    public LocalDateTime getJwtCreatedOn() {
        return jwtCreatedOn;
    }

    public void setJwtCreatedOn(LocalDateTime jwtCreatedOn) {
        this.jwtCreatedOn = jwtCreatedOn;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    public String getPasswordResetCode() {
        return PasswordResetCode;
    }

    public void setPasswordResetCode(String passwordResetCode) {
        PasswordResetCode = passwordResetCode;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", surname='" + surname + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", isActive=" + isActive +
                ", jwtCreatedOn=" + jwtCreatedOn +
                ", activationCode='" + activationCode + '\'' +
                ", PasswordResetCode='" + PasswordResetCode + '\'' +
                '}';
    }
}
