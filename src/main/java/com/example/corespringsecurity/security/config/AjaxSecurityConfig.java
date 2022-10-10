package com.example.corespringsecurity.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.example.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import com.example.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import com.example.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import com.example.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import com.example.corespringsecurity.security.provider.AjaxAuthenticationProvider;

@Configuration
@Order(0)
public class AjaxSecurityConfig {
	
	private AuthenticationConfiguration authenticationConfiguration;
	
	
    @Autowired
    private void setAjaxSecurityConfig(AuthenticationConfiguration authenticationConfiguration) {
        this.authenticationConfiguration = authenticationConfiguration;
    }

   
    /**
     * 1step
     * {@link com.example.corespringsecurity.security.provider.AjaxAuthenticationProvider} 구현체를 참조하여 처리
     * 빈 등록
     */
    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }
    
    
    /**
     * 2-1step
     * ajaxAuthenticationProvider 클래스를 매니저 providers에 추가 
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(ajaxAuthenticationProvider());
        return authenticationManager;
    }
    
    
    /**
     * 2-2step
     * {@link com.example.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler}
     * AuthenticationSuccessHandler 의 구현체로 로그인 성공 후 추가 작업 진행
     */
    public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
    	return new AjaxAuthenticationSuccessHandler();
    }
    
    
	/**
	 * 2-3step
	 * {@link com.example.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler}
	 * AuthenticationFailureHandler 의 구현체로 로그인 실패 후 추가 작업 진행
	 */
    public AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
    	return new AjaxAuthenticationFailureHandler();
    }
    
    
    public AjaxAccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }

    
	@Bean
	public SecurityFilterChain ajaxFilterChain(HttpSecurity http) throws Exception {
		
		http
				.antMatcher("/api/**")
				.authorizeRequests()
				.antMatchers("/api/messages").hasRole("MANAGER")
				.antMatchers("/api/users", "/api/login").permitAll()
				.anyRequest().authenticated()
				
        /**
         * addFilterBefore : 기존 클래스 앞에서 선 처리
         * addFilter : 가장 맨마지막
         * addFilterAfter : 기존 클래스 뒤에서 후 처리
         * addFilterAt : 기존 filter를 대체 처리
         * customConfigurerAjax 사용 시 주석
         */
       // http
       // 		.addFilterBefore(ajaxLoginProcessingFilter() , UsernamePasswordAuthenticationFilter.class );
        
        .and()
        		.exceptionHandling()
        		.authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
        		.accessDeniedHandler(ajaxAccessDeniedHandler());

		//http.csrf().disable();
		
		ajaxConfigurer(http);

		return http.build();
	}
	
	
	/**
	 * DSLs 구성 전략
	 */
    private void ajaxConfigurer(HttpSecurity http) throws Exception {
    	http
    			.apply(new AjaxLoginConfigurer<>())
    			.successHandlerAjax(ajaxAuthenticationSuccessHandler())
    			.failureHandlerAjax(ajaxAuthenticationFailureHandler())
    			.loginProcessingUrl("/api/login")
                .setAuthenticationManager(authenticationManager(this.authenticationConfiguration));
	}


	/**
     * 3step
     * {@link com.example.corespringsecurity.security.filter.AjaxLoginProcessingFilter} 구현체를 참조하여 처리
     * 비동기 인증 커스텀 처리
     * customConfigurerAjax 사용 시 주석
     */
//    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
//        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
//        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager(this.authenticationConfiguration));
//        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
//        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
//        return ajaxLoginProcessingFilter;
//    }

}
