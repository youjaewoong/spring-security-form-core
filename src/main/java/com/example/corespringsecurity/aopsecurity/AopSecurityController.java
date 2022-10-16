package com.example.corespringsecurity.aopsecurity;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.example.corespringsecurity.domain.dto.AccountDto;

import lombok.AllArgsConstructor;


/**
 * 메소드보안, 포인트컷 등 테스트 컨트롤러
 */
@Controller
@AllArgsConstructor
public class AopSecurityController {
	
    private final AopMethodService aopMethodService;
    private final AopPointcutService aopPointcutService;
    private final AopLiveMethodService aopLiveMethodService ;
    

	@GetMapping("/preAuthorize")
	@PreAuthorize("hasRole('ROLE_USER') AND #account.username == principal.username")
	public String preAuthorize(AccountDto account, Model model, Principal principal) {
		
		model.addAttribute("method", "Success @PreAuthorize");
		
		return "aop/method";
	}
	
	
	/**
	 * 메소드보안 테스트
	 * {@link com.example.corespringsecurity.security.factory.MethodResourcesMapFactoryBean}
	 * DB로 부터 얻은 권한/자원 정보를 ResourceMap을 빈으로 생성해서
	 * 
	 * {@link com.example.corespringsecurity.security.config.MethodSecurityConfig}
	 * map형태로 MapBasedMethodSecurityMetadataSource에 전달
	 */
    @GetMapping("/methodSecured")
    public String methodSecured(Model model){

        aopMethodService.methodSecured();
        model.addAttribute("method", "Success MethodSecured");

        return "aop/method";
    }
    
    
	/**
	 * 포인트컷 테스트
	 * {@link com.example.corespringsecurity.security.factory.MethodResourcesMapFactoryBean}
	 * DB로 부터 얻은 권한/자원 정보를 ResourceMap을 빈으로 생성해서
	 * 
	 * {@link com.example.corespringsecurity.security.config.MethodSecurityConfig}
	 * map형태로 protectPointcutPostProcessor에 전달
	 * 
	 * {@link com.example.corespringsecurity.security.processor.ProtectPointcutPostProcessor} 에서 처리
	 */
    @GetMapping("/pointcutSecured")
    public String pointcutSecured(Model model){

        aopPointcutService.notSecured();
        aopPointcutService.pointcutSecured(); // aop 대상으로 로그인 안한 상태면 로그인 해야함
        model.addAttribute("method", "Success PointcutSecured");

        return "aop/method";
    }

    
	/**
	 * 실시간메소드보안 테스트
	 */
    @GetMapping("/liveMethodSecured")
    public String liveMethodSecured(Model model){

        aopLiveMethodService.liveMethodSecured();
        model.addAttribute("method", "Success LiveMethodSecured");

        return "aop/method";
    }

}