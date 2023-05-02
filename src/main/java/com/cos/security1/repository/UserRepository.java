package com.cos.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.User;


public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username); // select * from user where username= username;
}
