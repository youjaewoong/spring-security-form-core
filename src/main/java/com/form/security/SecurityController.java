package com.form.security;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class SecurityController {

	@GetMapping
	public String index(HttpSession session) {
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		log.info("authentication :::: {}", authentication);
		
		SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		Authentication authentication1 = context.getAuthentication();
		log.info("authentication1 :::: {}", authentication1);
		
		return "home";
	}
	
	/**
	 * 별도의 thread의 저장 할 경우 
	 * SecurityContextHolder.MODE_INHERITABLETHREADLOCAL 로 처리
	 */
	@GetMapping("/thread")
	public String thread() {
		new Thread(
			new Runnable() {
				@Override
				public void run() {
					Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
					log.info("authentication :::: {}", authentication);
				}
			}
		).start();
		return "thread";
	}
	
	@GetMapping("/user")
	public String user() {
		return "user";
	}
	
	@GetMapping("/admin/pay")
	public String adminPay() {
		return "adminPay";
	}
	
	@GetMapping("/admin/**")
	public String admin() {
		return "admin";
	}
	
	@GetMapping("/denied")
	public String denied() {
		return "Access is denied";
	}
	
	@GetMapping("/login")
	public String login() {
		return "login";
	}
}
