package com.example.corespringsecurity.security.config;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.example.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import com.example.corespringsecurity.security.filter.PermitAllFilter;
import com.example.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import com.example.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import com.example.corespringsecurity.security.provider.CustomAuthenticationProvider;
import com.example.corespringsecurity.security.service.CustomUserDetailsService;
import com.example.corespringsecurity.security.voter.IpAddressVoter;
import com.example.corespringsecurity.service.SecurityResourceService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

	private AuthenticationConfiguration authenticationConfiguration;
	
    @Autowired
    private SecurityResourceService securityResourceService;

	/**
	 * {@link com.example.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler}
	 * AuthenticationSuccessHandler 의 구현체로 로그인 성공 후 추가 작업 진행
	 */
	@Autowired
	private AuthenticationSuccessHandler formAuthenticationSuccessHandler;

	/**
	 * {@link com.example.corespringsecurity.security.handler.CustomAuthenticationFailureHandler}
	 * AuthenticationFailureHandler 의 구현체로 로그인 실패 후 추가 작업 진행
	 */
	@Autowired
	private AuthenticationFailureHandler formAuthenticationFailureHandler;

	/**
	 * {@link com.example.corespringsecurity.security.common.FormAuthenticationDetailsSource}
	 * AuthenticationDetailsSource 의 구현체로 추가 인증 파라미터를 추가한다.
	 */
	@Autowired
	private AuthenticationDetailsSource<HttpServletRequest, ?> formWebAuthenticationDetailsSource;

	/**
	 * 비밀번호를 안전하게 암호화 하도록 제공
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {

		/*
		 * 암호화 변경 방법 String encodingId = "MD5"; Map<String, PasswordEncoder> encoders =
		 * new HashMap<>(); encoders.put("MD5", new
		 * MessageDigestPasswordEncoder("MD5")); return new
		 * DelegatingPasswordEncoder(encodingId, encoders)
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
	 * {@link com.example.corespringsecurity.security.handler.CustomAccessDeniedHandler}
	 * 구현체를 참조하여 처리 인가 실패 커스텀 처리
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
			web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // static files
			web.ignoring().antMatchers("/favicon.ico", "/resources/**", "/error"); // custom files ignoring
		};
	}

	
	/**
	 * {@link com.example.corespringsecurity.security.provider.CustomAuthenticationProvider}
	 * 구현체를 참조하여 처리 추가 인증 커스텀 처리
	 */
	@Bean
	public AuthenticationProvider authenticationProvider() {
		return new CustomAuthenticationProvider();
	}


	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authenticationProvider());
        authenticationManagerBuilder.parentAuthenticationManager(null);

      
        
        http
                .authorizeRequests()
                .anyRequest().authenticated()
        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formWebAuthenticationDetailsSource)
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll()
        .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler())
       
        // DB 인가처리
       .and()
       			.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
       	;
        
        http.csrf().disable();
        return http.build();
    }
	
	
	//**********************************************인가처리 START **************************************
	
	/**
	 * custom 인가 처리
	 * permitAllFilter 구현체에 인가대상 데이터를 셋팅하여 처리
	 * IpAddressVoter
	 */
	@Bean
	public PermitAllFilter customFilterSecurityInterceptor() throws Exception {
		PermitAllFilter permitAllFilter = new PermitAllFilter("/", "/login", "/user/login**");
		permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
		permitAllFilter.setAccessDecisionManager(affirmativeBased()); 
		permitAllFilter.setAuthenticationManager(authenticationManager(this.authenticationConfiguration));
		return permitAllFilter;
	}

	
	/**
	 * urlResourcesMapFactoryBean 
	 * Url방식의 인가처리대상 데이터 처리
	 * FilterInvocationSecurityMetadataSource
	 */
	@Bean
	public UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
		return new UrlFilterInvocationSecurityMetadataSource(
				urlResourcesMapFactoryBean().getObject(), 
				securityResourceService);
	}
	
	
	/**
	 * voter 심의 처리
	 * AffirmativeBased
	 */
	private AccessDecisionManager affirmativeBased() {
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
		return affirmativeBased;
	}
	
	
	/**
	 * 인가처리 할 대상 DB 로직관련 처리
	 */
	private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
		UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
		urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		return urlResourcesMapFactoryBean;
	}

	
	private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
		
		// 계층구조 처리
		List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
		accessDecisionVoters.add(new IpAddressVoter(securityResourceService));
		accessDecisionVoters.add(roleVoter()); // ROLE_ADMIN 만 가지고 있어도 하위계층 권한 부여
		
		//accessDecisionVoters.add(new RoleVoter()); // 기본 voter ROLE_ADMIN, ROLE_USER, ROLE_MANAGER 구조
		return accessDecisionVoters;
	}

	@Bean
	public AccessDecisionVoter<? extends Object> roleVoter() {
		RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHiearchy());
		return roleHierarchyVoter;
	}

	
	@Bean
	public RoleHierarchyImpl roleHiearchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		return roleHierarchy;
	}
	
	//**********************************************인가처리 END **************************************

}
