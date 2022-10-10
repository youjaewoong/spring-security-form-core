package com.example.corespringsecurity.security.config;

import com.example.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import com.example.corespringsecurity.security.provider.CustomAuthenticationProvider;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
//    @Bean
//    public UserDetailsManager users() {
//
//        String password = passwordEncoder().encode("1111");
//
//        UserDetails user = User.builder()
//                .username( "user" )
//                .password( password )
//                .roles( "USER" )
//                .build();
//
//        UserDetails manager = User.builder()
//                .username("manager")
//                .password( password )
//                .roles("MANAGER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password( password )
//                .roles("ADMIN", "MANAGER", "USER")
//                .build();
//
//        return new InMemoryUserDetailsManager( user, manager, admin );
//    }


    /**
     * {@link com.example.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler}
     * AuthenticationSuccessHandler 의 구현체로 로그인 성공 후 추가 작업 진행
     */
    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    
	/**
	 * {@link com.example.corespringsecurity.security.handler.CustomAuthenticationFailureHandler}
	 * AuthenticationFailureHandler 의 구현체로 로그인 실패 후 추가 작업 진행
	 */
    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;
    

    /**
     * {@link com.example.corespringsecurity.security.common.FormAuthenticationDetailsSource}
     * AuthenticationDetailsSource 의 구현체로 추가 인증 파라미터를 추가한다.
     */
    @Autowired
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    

    /**
     * 비밀번호를 안전하게 암호화 하도록 제공
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
    	
    	/*
    	 * 암호화 변경 방법
    	String encodingId = "MD5";
    	Map<String, PasswordEncoder> encoders = new HashMap<>();
    	encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
    	return new DelegatingPasswordEncoder(encodingId, encoders)
    	*/	   
    			   
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    /**
     * {@link CustomUserDetailsService} 구현체를 참조하여 처리
     */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }
    

    /**
     * {@link com.example.corespringsecurity.security.provider.CustomAuthenticationProvider} 구현체를 참조하여 처리
     * 추가 인증 커스텀 처리
     */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }
    
    
    /**
     * {@link com.example.corespringsecurity.security.handler.CustomAccessDeniedHandler} 구현체를 참조하여 처리
     * 인가 실패 커스텀 처리
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }
    
    
    /**
     * 필터를 거치지 않으며 보안필터를 적용할 필요가 없는 리소스 설정
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()); //static files ignoring
            web.ignoring().antMatchers("/favicon.ico", "/resources/**", "/error"); // custom files ignoring
        };
    }
    
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/", "/users", "user/login/**", "/login*").permitAll() // login/* params까지 처리 
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/message").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated();

        http
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll();

        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());

        return http.build();
    }
}
