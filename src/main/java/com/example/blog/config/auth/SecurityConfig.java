package com.example.blog.config.auth;

import com.example.blog.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@RequiredArgsConstructor
@EnableWebSecurity //스프링 서큐리티 설정들을 활성
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .csrf().disable()
                .headers().frameOptions().disable()//h2-console 사용하기 위해
                .and()
                    .authorizeHttpRequests() //Url 권한 설정 옵션의 시작점
                    .antMatchers("/","/css/**","/images/**",    //권한 관리 대상을 지정하는 옵션
                            "/js/**","/h2-console/**").permitAll()
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                    .anyRequest().authenticated()   //설정된 값들 이외 나머지 URL들을 나타냄
                    .and()
                        .logout()
                            .logoutSuccessUrl("/")  //로그아웃 기능에 대한 여러 설정의 진입점
                .and()
                    .oauth2Login()      //oauth2 로그인 기능에 대한 여러 설정의 진입점
                        .userInfoEndpoint()     //로그인 성공 이후 사용자 정보를 가져올 때의 설정들
                            .userService(customOAuth2UserService);     // 소셜 로그인 성공 시 후속 조치를 진행할 UserServic 인터페이스의 구현체를 등록
    }
}
