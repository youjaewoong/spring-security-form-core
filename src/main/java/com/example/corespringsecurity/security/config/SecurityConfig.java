package com.example.corespringsecurity.security.config;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
public class SecurityConfig {

	private AuthenticationConfiguration authenticationConfiguration;
	
    @Autowired
    private SecurityResourceService securityResourceService;

	/**
	 * {@link com.example.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler}
	 * AuthenticationSuccessHandler ??? ???????????? ????????? ?????? ??? ?????? ?????? ??????
	 */
	@Autowired
	private AuthenticationSuccessHandler formAuthenticationSuccessHandler;

	/**
	 * {@link com.example.corespringsecurity.security.handler.CustomAuthenticationFailureHandler}
	 * AuthenticationFailureHandler ??? ???????????? ????????? ?????? ??? ?????? ?????? ??????
	 */
	@Autowired
	private AuthenticationFailureHandler formAuthenticationFailureHandler;

	/**
	 * {@link com.example.corespringsecurity.security.common.FormAuthenticationDetailsSource}
	 * AuthenticationDetailsSource ??? ???????????? ?????? ?????? ??????????????? ????????????.
	 */
	@Autowired
	private AuthenticationDetailsSource<HttpServletRequest, ?> formWebAuthenticationDetailsSource;

	/**
	 * ??????????????? ???????????? ????????? ????????? ??????
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {

		/*
		 * ????????? ?????? ?????? String encodingId = "MD5"; Map<String, PasswordEncoder> encoders =
		 * new HashMap<>(); encoders.put("MD5", new
		 * MessageDigestPasswordEncoder("MD5")); return new
		 * DelegatingPasswordEncoder(encodingId, encoders)
		 */

		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	
	/**
	 * {@link CustomUserDetailsService} ???????????? ???????????? ??????
	 */
	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
		return authConfiguration.getAuthenticationManager();
	}
	

	/**
	 * {@link com.example.corespringsecurity.security.handler.CustomAccessDeniedHandler}
	 * ???????????? ???????????? ?????? ?????? ?????? ????????? ??????
	 */
	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
		accessDeniedHandler.setErrorPage("/denied");
		return accessDeniedHandler;
	}

	
	/**
	 * ????????? ????????? ????????? ??????????????? ????????? ????????? ?????? ????????? ??????
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
	 * ???????????? ???????????? ?????? ?????? ?????? ????????? ??????
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
       
        // DB ????????????
       .and()
       			.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
       	;
        
        http.csrf().disable();
        
        return http.build();
    }
	
	
	//**********************************************???????????? START **************************************
	
	/**
	 * custom ?????? ??????
	 * permitAllFilter ???????????? ???????????? ???????????? ???????????? ??????
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
	 * Url????????? ?????????????????? ????????? ??????
	 * FilterInvocationSecurityMetadataSource
	 */
	@Bean
	public UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
		return new UrlFilterInvocationSecurityMetadataSource(
				urlResourcesMapFactoryBean().getObject(), 
				securityResourceService);
	}
	
	
	/**
	 * voter ?????? ??????
	 * AffirmativeBased
	 */
	private AccessDecisionManager affirmativeBased() {
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecisionVoters());
		return affirmativeBased;
	}
	
	
	/**
	 * ???????????? ??? ?????? DB ???????????? ??????
	 */
	private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
		UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
		urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		return urlResourcesMapFactoryBean;
	}

	
	private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
		
		// ???????????? ??????
		List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
		accessDecisionVoters.add(new IpAddressVoter(securityResourceService));
		accessDecisionVoters.add(roleVoter()); // ROLE_ADMIN ??? ????????? ????????? ???????????? ?????? ??????
		
		//accessDecisionVoters.add(new RoleVoter()); // ?????? voter ROLE_ADMIN, ROLE_USER, ROLE_MANAGER ??????
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
	
	//**********************************************???????????? END **************************************

}
