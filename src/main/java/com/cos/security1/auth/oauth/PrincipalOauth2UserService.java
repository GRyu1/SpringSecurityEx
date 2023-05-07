package com.cos.security1.auth.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.auth.oauth.provider.FacebookUserInfo;
import com.cos.security1.auth.oauth.provider.GoogleUserInfo;
import com.cos.security1.auth.oauth.provider.NaverUserInfo;
import com.cos.security1.auth.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    @Autowired
    private UserRepository userRepository;
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequset : "+userRequest.getClientRegistration());
        System.out.println("userRequset : "+userRequest.getAccessToken().getTokenValue());
        System.out.println("useGetAttribute : "+super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글 로그인 버튼 클릭 -> 로그인창 -> 로근인을 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken 요청
        //userRequest 정보 -> 회원프로필 받아야함 (loadUser함수) 호출 -> 구글로 부터 회원프로필을 받아줌.
        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }
        else{
            System.out.println("구글 페북 네이버만 지원됩니다.");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider+"_"+providerId;
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";
        // 회원가입 진행.
        User userEntity = this.userRepository.findByUsername(username);
        if(userEntity == null){
            System.out.println(provider+"로그인이 최초입니다.");
            userEntity = User.builder()
                            .username(username)
                                    .password(password)
                                            .email(email)
                                                    .role(role)
                                                            .provider(provider)
                                                                    .providerId(providerId).build();
            userRepository.save(userEntity);
        }else{
            System.out.println("구글 로그인입니다. 자동회원가입은 되어 있습니다.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
    /*
    회원가입 연동
    username : google_super.loadUser(userRequest).getAttributes().sub
    password : "암호화(get in there)"
    email : super.loadUser(userRequest).getAttributes().email
    role : ROLE_USER
    provider : google
    provider id : super.loadUser(userRequest).getAttributes().sub

    * */
}
