package com.cos.security1.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//Security Config에서 loginProcessing Url("/login");
//login 요청이 오면 자동으로 UserDetailsService 타입으로 Ioc 되어있는 LoadUserByUsername 함수가 실행.
@Service
public class PrincipalDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    // S.session [ Authentication [ "UserDetails(여기해당하는 것을 리턴함.)" ] ]
    @Override
    public UserDetails loadUserByUsername(String username/*로그인 form 의 파라미터*/) throws UsernameNotFoundException {
        System.out.println("Username : "+ username);
        User userEntity = userRepository.findByUsername(username);
        if(userEntity != null){
            System.out.println("로그인 성공");
            return new PrincipalDetail(userEntity);
        }
        return null;
    }
}
