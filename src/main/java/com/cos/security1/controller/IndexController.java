package com.cos.security1.controller;


import com.cos.security1.auth.PrincipalDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/test/login")
	public @ResponseBody String loginTest(
			Authentication authentication,
			@AuthenticationPrincipal PrincipalDetails userDetails
	){ //DI(의존성 주입) : authentication[principal]
		System.out.println("/test/login ===============");
		PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
		System.out.println("authentication"+ principalDetails.getUser());

		System.out.println("userDetails : "+userDetails.getUser());
		return "세션정보 확인하기";
	}

	@GetMapping("/test/oauth/login")
	public @ResponseBody String loginOAuthTest(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oAuth
	){ //DI(의존성 주입) : authentication[principal]
		System.out.println("/test/OAuth/login ===============");
		OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
		System.out.println("authentication"+ oAuth2User.getAttributes());
		System.out.println("oauth2 : "+oAuth.getAttributes() );
		return "OAuth 세션정보 확인하기";
	}


	@GetMapping({"","/"})
	public @ResponseBody String index() {
		return "index";
	}

	//OAuth 로그인을 해도 principalDetails
	//일반 로그인을 해도 principalDetails
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails : "+principalDetails.getUser());
		return "user";
	}

	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}

	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}

	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}

	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}

	@PostMapping("/join")
	public String join(User user) {
		System.out.println(user.toString());
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		this.userRepository.save(user);

		System.out.println(user.toString());
		return "redirect:/loginForm";
	}

	@Secured({"ROLE_ADMIN"})
	@GetMapping("/info")
	public @ResponseBody String info(){
		return "개인정보";
	}

	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") //PostAuthorize 함수끝나고 걸림
	@GetMapping("/data")
	public @ResponseBody String data(){
		return "데이터 정보";
	}

}
