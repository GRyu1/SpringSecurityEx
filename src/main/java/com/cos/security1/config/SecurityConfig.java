package com.cos.security1.config;

import com.cos.security1.auth.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
// 구글 로그인 성공 후 처리 1. 코드받기인증 2. 엑세스 토크 권한 3.사용자 프로필을 가져옴
// 4-1 가져온 토큰으로 회원가입을 자동 진행
// 4-2 이메일 전화번호 이름 아이디 쇼핑몰 등등 가져옴. 회원가입 추가정보 진행.
// (엑세스 토큰 + 사용자 프로필 정보 O)

@Configuration
@EnableWebSecurity // 스프링시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)//preAuthorize,PostAuthorize 어노테이션 활성화
public class SecurityConfig{
	
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeHttpRequests()
                .requestMatchers("/user/**").authenticated()
                .requestMatchers("/manager/**").hasAnyRole("MANAGER","ADMIN") //시큐리티 설정은 "ADMIN" <=> USER DB 에는 "ROLE_ADMIN"
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // login주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줌. >> 컨트롤러에서 로그인맵핑이 필요없다.
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);


        return http.build();
    }

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

	@Bean
	public BCryptPasswordEncoder PWencoder() {
		return new BCryptPasswordEncoder();
	}
}
