package com.example.corespringsecurity.security.provider;

import com.example.corespringsecurity.security.common.FormWebAuthenticationDetails;
import com.example.corespringsecurity.security.service.AccountContext;
import com.example.corespringsecurity.security.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        // password 인증
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);
        if ( !passwordEncoder.matches( password, accountContext.getAccount().getPassword() ) ) {
            throw new BadCredentialsException( "BadCredentialsException" );
        }

        // 커스텀 시크릿 키 인증
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretkey = formWebAuthenticationDetails.getSecretkey();
        if (secretkey == null || !"secret".equals(secretkey)) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }
        
        // 인증정보를 proiver에게 전달
        return new UsernamePasswordAuthenticationToken(
        		accountContext.getAccount(), 
        		null, 
        		accountContext.getAuthorities());
    }

    
    /**
     * 토큰 유효성 체크
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom( authentication );
    }

}
