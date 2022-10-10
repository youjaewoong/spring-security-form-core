package com.example.corespringsecurity.security.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.corespringsecurity.security.filter.AjaxLoginProcessingFilter;


/**
 * Custom DSLs
 */
public final class AjaxLoginConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {
	
	private AuthenticationSuccessHandler successHandler;
	private AuthenticationFailureHandler failureHandler;
	private AuthenticationManager authenticationManager;

	
	public AjaxLoginConfigurer() {
		super(new AjaxLoginProcessingFilter(), null);
	}

	
	// 초기화
	@Override
	public void init(H http) throws Exception {
		super.init(http);
	}

	
	// 설정
	@Override
	public void configure(H http) {
		// 공유객체
		if (authenticationManager == null) {
			authenticationManager = http.getSharedObject(AuthenticationManager.class);
		}

		getAuthenticationFilter().setAuthenticationManager(authenticationManager);
		getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
		getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);

		// 세션 관련
		SessionAuthenticationStrategy sessionAuthenticationStrategy = http
				.getSharedObject(SessionAuthenticationStrategy.class);
		if (sessionAuthenticationStrategy != null) {
			getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		}
		
		// rememberMe 관련
		RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
		if (rememberMeServices != null) {
			getAuthenticationFilter().setRememberMeServices(rememberMeServices);
		}

		// 공유객체에 ajax filter 저장
		http.setSharedObject(AjaxLoginProcessingFilter.class, getAuthenticationFilter());
		http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	
	public AjaxLoginConfigurer<H> successHandlerAjax(AuthenticationSuccessHandler successHandler) {
		this.successHandler = successHandler;
		return this;
	}

	
	public AjaxLoginConfigurer<H> failureHandlerAjax(AuthenticationFailureHandler authenticationFailureHandler) {
		this.failureHandler = authenticationFailureHandler;
		return this;
	}

	
	public AjaxLoginConfigurer<H> setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	
	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl, "POST");
	}
}