package com.develhope.login.auth.entities;

public class RestorePasswordDTO {

    private String newPassword;
    private String resetPasswordCode;

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getResetPasswordCode() {
        return resetPasswordCode;
    }

    public void setResetPasswordCode(String resetPasswordCode) {
        this.resetPasswordCode = resetPasswordCode;
    }

    @Override
    public String toString() {
        return "RestorePasswordDTO{" +
                "newPassword='" + newPassword + '\'' +
                ", resetPasswordCode='" + resetPasswordCode + '\'' +
                '}';
    }
}
