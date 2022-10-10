package com.example.corespringsecurity.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * 추가적인 파라미터 저장하는 클래스
 * 추가적인 인증
 */
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

	private static final long serialVersionUID = -8734446806917170334L;
	private String secretkey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.secretkey = request.getParameter("secret_key");
    }

    public String getSecretkey() {
        return secretkey;
    }
}
