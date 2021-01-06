package io.example.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/** 용석 : 2020-12-31
 * Spring Security 설정 추가
 * 의존성 : spring-boot-starter-security
 * 목적 : WebSecurityConfigurerAdapter의 cofigure() 상속 후 Override 하여 Custom 인증/인가 추가
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    /** 용석 : 2021-01-03
     * configure(HttpSecurity http) 재 정의를 통해 시스템에 필요한 사용자 정의 인가/인증 정책을 설정
     * - HttpSecurity : 인가/인증 설정 관련 기능 제공
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /* HttpSecurity.authorizeRequests() 재 정의를 통한 인가 정책 설정 */
        http.authorizeRequests()
                .anyRequest().authenticated()
        ;

        /* HttpSecurity.formLogin() 재 정의를 통한 로그인 정책 설정 */
        http.formLogin()
//                .loginPage("/custom_login")                 // 로그인 페이지 경로 설정
                .defaultSuccessUrl("/api/index")            // 로그인 성공 시 화면 이동 경로 설정
                .failureForwardUrl("/login")                // 로그인 실패 시 화면 이동 경로 설정
                .usernameParameter("custom_username")       // 로그인 폼 요청 시 기본값으로 설정된 username에 해당하는 파라미터 명 설정
                .passwordParameter("custom_password")       // 로그인 폼 요청 시 기본값으로 설정된 password에 해당하는 파라미터 명 설정
                .loginProcessingUrl("/custom_login")        // 로그인 폼 요청 시 기본값으로 설정된 "/login" action URL 설정
                // 로그인 성공 시 Handler를 통한 추가 처리 설정
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest
                            , HttpServletResponse httpServletResponse
                            , Authentication authentication) throws IOException, ServletException {
                        log.info(authentication.getName());   // 로그인 요청 사용자에 대한 정보 접근 가능
                        httpServletResponse.sendRedirect("/api/index"); // 로그인 성공 이후 response 객체 접근 가능
                    }
                })
                // 로그인 실패 시 Handler를 통한 추가 처리 설정
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest
                            , HttpServletResponse httpServletResponse
                            , AuthenticationException e) throws IOException, ServletException {
                        log.error(e.getMessage()); // 로그인 실패 Exception 객체 접근 가능
                        httpServletResponse.sendRedirect("/login"); // response를 통해 로그인 실패 후 처리 가능
                    }
                })

                /*
                 * formLogin() 인증 방식에서 설정한 loginPage({loginPage path})의 경로에는
                 * 인가 정책이 적용되지 않고 누구나 접근 가능하도록 설정
                 */
                .permitAll()
        ;

        /* HttpSecurity.logout() 재 정의를 통한 로그아웃 정책 설정 */
        http.logout()
                .logoutUrl("/logout")                       // 로그아웃 처리 경로 설정 -> 기본 설정은 'POST 요청'
                .logoutSuccessUrl("/login")                 // 로그아웃 성공 시 화면 이동 경로 설정
                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 성공 시 삭제해야할 Client에게 발급한 쿠키 목록
                // 로그아웃 성공 시 세션 무효화, 인증 토큰 삭제 외에 추가 처리 설정
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        // 로그아웃 성공 시 세션 무효화 처리
                        HttpSession httpSession = httpServletRequest.getSession();
                        httpSession.invalidate();
                    }
                })
                // 로그아웃 성공 시 Handler를 통한 추가 처리 설정
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
        ;

        /* HttpSecurity.rememberMe() 재 정의를 통한 remember-me 정책 설정 */
        http.rememberMe()
                .rememberMeParameter("remember-me")     // 로그인 폼 요청 시 기본값으로 설정된 remember-me에 해당하는 파라미터 명 설정
                .tokenValiditySeconds(3600)             // 쿠키 만료 기간 default : 14일, 단위 = 초
//                .alwaysRemember(false)                  // remember-me 기능 항상 실행 여부
                .userDetailsService(userDetailsService) // remember-me 기능 수행 시 사용자 정보 조회를 위한 service 설정
        ;

        /* HttpSecurity.sessionManagement() 재 정의를 통한 동시 세션 제어 정책 설정 */
        http.sessionManagement()
                .invalidSessionUrl("/login")        // 유요하지 못한 세션인 경우 이동 화면 경로
                .maximumSessions(1)                 // 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false)    // 동시 로그인 차단 설정, false : 기존 세션 만료(default)
                .expiredUrl("/login")               // 세션 만료 시 이동 화면 경로
        ;

        /* HttpSecurity.sessionManagement() 재 정의를 통한 세션 고정 보호 정책 설정 */
        http.sessionManagement()
                .sessionFixation().changeSessionId()    // 인증 요청 시 이전 세션 정보를 이용하여 신규 세션 발급 (servlet 3.1 이상) -> 기본값
//                .sessionFixation().migrateSession()     // 인증 요청 시 이전 세션 정보를 이용하여 신규 세션 발급 (servlet 3.1 이하)
//                .sessionFixation().none()               // 인증 요청 시 신규 session을 발급 하지 않음
//                .sessionFixation().newSession()         // 인증 요청 시 이전 세션정보의 속성을 참조 하지 않는 새로운 세션 발급
        ;
    }
}

