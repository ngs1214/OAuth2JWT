package com.example.OAuth2JWT.service;

import com.example.OAuth2JWT.dto.*;
import com.example.OAuth2JWT.entity.UserEntity;
import com.example.OAuth2JWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    //OAuth2UserService도 상관없음
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        //구현
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        String role = null;
        UserEntity findUser = userRepository.findByUsername(username);
        if (findUser != null) {
            role = findUser.getRole();

            findUser.setEmail(oAuth2Response.getEmail());
            findUser.setName(oAuth2User.getName());

            userRepository.save(findUser);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(findUser.getUsername());
            userDTO.setName(oAuth2User.getName());
            userDTO.setRole(findUser.getRole());

            return new CustomOAuth2User(userDTO);
        } else {
            //없는경우
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setRole("ROLE_ADMIN");
            userRepository.save(userEntity);

            UserDTO userDTO = new UserDTO();
            userDTO.setName(username);
            userDTO.setName(oAuth2User.getName());
            userDTO.setRole("ROLE_USER");

            return new CustomOAuth2User(userDTO);
        }
    }
}
