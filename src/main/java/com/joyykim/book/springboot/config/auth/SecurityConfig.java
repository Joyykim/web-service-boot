package com.joyykim.book.springboot.config.auth;

import com.joyykim.book.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity //Spring Security 설정 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //h2-console 화면을 사용하기 위해 옵션 disable
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()

                //URL별 권한 관리 옵션 진입점
                .authorizeRequests()
                //권한 관리 대상을 지정하는 옵션 - URL, HTTP 메소드별로 관리 가능
                .antMatchers("/", "/css/**", "/images/**", "/js/**", "/h2-console/**", "/profile")
                .permitAll()
                .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                .anyRequest().authenticated() //설정된 값들 이외 나머지 요청은 인증(로그인) 필요
                .and()

                //로그아웃 기능 설정 진입점
                .logout()
                .logoutSuccessUrl("/") //로그아웃 성공시 "/"으로 이동
                .and()

                //OAuth2 로그인 기능 설정 진입점
                .oauth2Login()
                .userInfoEndpoint() //OAuth2 로그인 성공 후 사용자 정보 가져올 때의 설정
                //후속 조치 진행할 UserService 인터페이스의 구현체 등록
                //리소스 서버(소셜 서비스)에서 사용자 정보를 가져온 상태에서 추가로 진행할 기능을 명시
                .userService(customOAuth2UserService);
    }
}
