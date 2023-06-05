package com.develhope.login.users.repositories;

import com.develhope.login.users.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {

    User findByEmail(String email);

    User getByActivationCode(String activationCode);

    User findByPasswordResetCode(String passwordResetCode);
}
