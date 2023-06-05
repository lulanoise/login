package com.develhope.login.auth.entities;

public class RequestPasswordDTO {

    private String email;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "RequestPasswordDTO{" +
                "email='" + email + '\'' +
                '}';
    }
}
