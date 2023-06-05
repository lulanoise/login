package com.develhope.login.auth.entities;

import com.develhope.login.users.entities.User;

public class LoginRTO {

   private User user;
   private String JWT;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getJWT() {
        return JWT;
    }

    public void setJWT(String JWT) {
        this.JWT = JWT;
    }

    @Override
    public String toString() {
        return "LoginRTO{" +
                "user=" + user +
                ", JWT='" + JWT + '\'' +
                '}';
    }
}
