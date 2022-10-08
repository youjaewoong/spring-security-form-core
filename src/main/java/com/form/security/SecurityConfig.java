package com.form.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	UserDetailsService userDetailsService;
	
	@Bean
	public UserDetailsManager users() {

	    UserDetails user = User.builder()
	            .username("user")
	            .password("{noop}1111")
	            .roles("USER")
	            .build();

	    UserDetails sys = User.builder()
	            .username("sys")
	            .password("{noop}1111")
	            .roles("SYS")
	            .build();

	    UserDetails admin = User.builder()
	            .username("admin")
	            .password("{noop}1111")
	            .roles("ADMIN", "SYS", "USER")
	            .build();
	    return new InMemoryUserDetailsManager( user, sys, admin );
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		//인가 정책
		//설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 한다.
		http
			.antMatcher("/**")
			.authorizeRequests()
			.antMatchers("/login").permitAll()
			.antMatchers("/user").hasRole("USER")
			.antMatchers("/admin/pay").hasRole("ADMIN")
			.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
			.antMatchers("/shop/login", "/shop/users/**").hasRole("USER")
			.antMatchers("/shop/mypage").hasRole("USER")
			.antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
			.antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
			.anyRequest().authenticated();
		
		//인증 정책
		http.formLogin()							// UsernamePasswordAuthenticationFilter
			//.loginPage("/loginPage")				// 사용자 정의 로그인 페이지
		 	.defaultSuccessUrl("/")					// 로그인 성공 후 이동 페이지
            .failureUrl("/login")					// 로그인 실패 후 이동 페이지
            .usernameParameter("userId")			// 아이디 파라미터명 설정
            .passwordParameter("password")			// 패스워드 파라미터명 설정
            .loginProcessingUrl("/login_proc")		// 로그인 Form Action Url
            .successHandler(loginSuccessHandler())	// 로그인 성공 후 핸들러
            .failureHandler(loginFailureHandler())	// 로그인 실패 후 핸들러
            .permitAll(); 							// 모든 사용자 접근권한
		
		//csrf 기능은 기본 설정되어있음
		http.csrf().disable();
        
		// 동시 세션 제어
        http.sessionManagement() 				// SessionManagementFilter, ConcurrentSessionFilter
        	//.invalidSessionUrl("/invalid")	// 세션이 유효하지 않을 떄 이동 할 페이지
        	.maximumSessions(1)					// 최대 허용 가능 세션 수 , -1:무제한 로그인 세션 허용
        	// 1. 이전 사용자 세션 만료 전략 false : 기존 세션 만료(defalut)
        	// 2. 현재 사용자 인증 실패 전략 true : 동시 로그인 차단함,
			.maxSessionsPreventsLogin(false);
			//.expiredUrl("/expired"); 			// 세션이 만료된 경우 이동 할 페이지
        
        // 세션 고정보호
        http.sessionManagement()
        	.sessionFixation()
        	.changeSessionId(); 	// default 서블릿 스팩 3.1 이상 Jsession 요청마다 생성
        	//.migrateSession() 	// 서블릿 3.1 이하의 Jsession이 요청마다 생성
        	//.newSession() 		// Jsession 생성 및 속성값 요청마다 생성 
        	//.none(); 				// Jsession 동일 보안 이슈 발생
        	
        // 세션 정책
        // SessionCreationPolicy.Always : 스프링 시큐리티가 항상 세션 생성
        // SessionCreationPolicy.If_Required : 스프링 시큐리티가 필요 시 생성(기본값)
        // SessionCreationPolicy.Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
        // SessionCreationPolicy.Stateless : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음 (jwt 사용시) 
        http.sessionManagement()
        	.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        
		http.logout() 								// LogutFilter
			.logoutUrl("/logout") 					// 로그아웃 처리 URL
			.logoutSuccessUrl("/login") 			// 로그아웃 성공 후 이동페이지
			.deleteCookies("JSESSIONID", "remember-me") 	// 로그아웃 후 쿠키 삭제
			.addLogoutHandler(logoutHandler())	 			// 로그아웃 핸들러
			.logoutSuccessHandler(logoutSuccessHandler());	// 로그아웃 성공 후 핸들러
		
		http.rememberMe()							// RememberMeAuthenticationFilter
			.rememberMeParameter("remember")		// 기본 파라미터명은 remember-me
			.tokenValiditySeconds(3600)				// Default 는 14일
			.alwaysRemember(false)					// 리멤버 미 기능이 활성화되지 않아도 항상 실행
			.userDetailsService(userDetailsService);
		
		//인증/인가 예외처리 기능
		http.exceptionHandling()
			//.authenticationEntryPoint(authenticationEntryPoint())	//인증 exception 처리 주석 시 기본 스프링 로그인
			.accessDeniedHandler(accessDeniedHandler());			//인가 exception 처리
		
		//throlad local 저장 전략 처리
		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL); // 자식 thread 공유 전략

		return http.build();
	}

	
	private AccessDeniedHandler accessDeniedHandler() {
		return new AccessDeniedHandler() {
			@Override
			public void handle(HttpServletRequest request, HttpServletResponse response,
					AccessDeniedException accessDeniedException) throws IOException, ServletException {
				System.out.println("AccessDeniedHandler :: ");
				response.sendRedirect("/denied");
			}
		};
	}

	private AuthenticationEntryPoint authenticationEntryPoint() {
		return new AuthenticationEntryPoint() {
			@Override
			public void commence(HttpServletRequest request, HttpServletResponse response,
					AuthenticationException authException) throws IOException, ServletException {
				System.out.println("AuthenticationEntryPoint :: ");
				response.sendRedirect("/login");
			}
		};
	}

	private LogoutSuccessHandler logoutSuccessHandler() {
		return new LogoutSuccessHandler() {
			@Override
			public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
					throws IOException, ServletException {
				System.out.println("LogoutSuccessHandler :: ");
				response.sendRedirect("/login");
			}
		};
	}

	
	private LogoutHandler logoutHandler() {
		return new LogoutHandler() {
			@Override
			public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
				HttpSession session = request.getSession();
				session.invalidate();
			}
		};
	}


	private AuthenticationSuccessHandler loginSuccessHandler() {
		return new AuthenticationSuccessHandler() {
			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				
				//인증에 성공하면 cache에 담겨져 있던 url 처리
				RequestCache requestCache = new HttpSessionRequestCache();
				SavedRequest saveReqeust = requestCache.getRequest(request, response);
				String redirectUrl = saveReqeust.getRedirectUrl();
				System.out.println("AuthenticationSuccessHandler :: " + authentication.getName());
				response.sendRedirect(redirectUrl);
				
				//response.sendRedirect("/");
			}
		};
	}
	
	
	private AuthenticationFailureHandler loginFailureHandler() {
		return new AuthenticationFailureHandler() {
			
			@Override
			public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
					AuthenticationException exception) throws IOException, ServletException {
				
				System.out.println("AuthenticationFailureHandler :: " + exception.getMessage());
				response.sendRedirect("/login");
			}
		};
	}
}