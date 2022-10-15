package com.example.corespringsecurity.security.filter;

import com.example.corespringsecurity.domain.dto.AccountDto;
import com.example.corespringsecurity.security.token.AjaxAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 비동기 요청이 올 경우 처리
 */
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    //해당 조건일 경우 필터처리
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (!isAjax(request) ) {
            throw new IllegalStateException( "Authentication is not supported" );
        }

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        if ( accountDto.getUsername().isEmpty() || accountDto.getPassword().isEmpty() ) {
            throw new IllegalArgumentException( "Username or Password is empty" );
        }

        // 인증 전 토근정보를 매니저에게 전달
        AjaxAuthenticationToken ajaxAuthenticationToken = 
        		new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    private boolean isAjax(HttpServletRequest request) {

        if ("XMLHttpRequest".equals( request.getHeader( "X-Requested-With" ))) {
            return true;
        }
        return false;
    }
}
