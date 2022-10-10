package com.example.corespringsecurity.security.provider;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.corespringsecurity.security.service.AccountContext;
import com.example.corespringsecurity.security.token.AjaxAuthenticationToken;


@Component
public class AjaxAuthenticationProvider implements AuthenticationProvider {
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private PasswordEncoder passwordEncoder;


	@Override
	@Transactional
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        // password 인증
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);
        if ( !passwordEncoder.matches( password, accountContext.getAccount().getPassword() ) ) {
            throw new BadCredentialsException( "BadCredentialsException" );
        }

        // 인증 후 인증에 성공한 결과를 담는 생성자
        // authentcation manager 에게 전달 -> 매니저는 인증처리하는 필터에게 전달
		return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(AjaxAuthenticationToken.class);
	}
}