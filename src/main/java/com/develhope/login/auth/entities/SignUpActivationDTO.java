package com.develhope.login.auth.entities;

public class SignUpActivationDTO {

    private String activationCode;

    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    @Override
    public String toString() {
        return "SignUpActivationDTO{" +
                "activationCode='" + activationCode + '\'' +
                '}';
    }
}
