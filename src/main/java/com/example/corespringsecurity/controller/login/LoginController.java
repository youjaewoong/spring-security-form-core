package com.example.corespringsecurity.controller.login;

import com.example.corespringsecurity.domain.Account;
import com.example.corespringsecurity.security.common.FormWebAuthenticationDetails;
import com.example.corespringsecurity.security.service.AccountContext;
import com.example.corespringsecurity.security.token.AjaxAuthenticationToken;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

	
	/**
	 * {@link com.example.corespringsecurity.security.handler.CustomAuthenticationFailureHandler}
	 * 로그인 실패시 에러 핸들러에서 처리된 파라미터를 받는다.
	 */
	@GetMapping(value = { "/login", "/api/login" })
	public String login(@RequestParam(value = "error", required = false) String error,
			@RequestParam(value = "exception", required = false) String exception, Model model) {
		
		model.addAttribute("error", error);
		model.addAttribute("exception", exception);

		return "/user/login/login";
	}

	
	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication != null) {
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}
		return "redirect:/";
	}
	

	@GetMapping(value = { "/denied", "/api/denied" })
	public String accessDenied(@RequestParam(value = "exception", required = false) String exception,
			Principal principal, Model model) throws Exception {

		Account account = null;

		if (principal instanceof UsernamePasswordAuthenticationToken) {
			account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();

		} else if (principal instanceof AjaxAuthenticationToken) {
			account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
		}
		
		model.addAttribute("username", account.getUsername());
		model.addAttribute("exception", exception);

		return "/user/login/denied";
	}

}
