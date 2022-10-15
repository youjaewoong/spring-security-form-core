package com.example.corespringsecurity.security.metadatasource;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.corespringsecurity.service.SecurityResourceService;

/**
 * 사용자가 접근하고자 하는 Url 자원에 대한 권한 정보 추출
 * AccessDecisionManager 에게 전달하여 인가처리 수행
 * DB로부터 자원 및 권한 정보를 매핑하여 맵으로 관리
 * 사용자의 매 요청마다 요청정보에 매핑된 권한정보 확인
 * 
 * UrlFilterInvocationSecurityMetadataSource
 *  -> FilterInvocationSecurityMetadataSource
 * 	 -> SecuritMetadatSource	   
 */
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

	// 권한정보를 담는 객체
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap;

    private SecurityResourceService securityResourceService;


    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap, 
    		SecurityResourceService securityResourceService) {
    	
    	this.securityResourceService = securityResourceService;
		this.requestMap = requestMap;
	}

	@Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        
        
        // DB정보를 셋팅하여 활용
        //requestMap.put(new AntPathRequestMatcher("/mypage"), Arrays.asList(new SecurityConfig("ROLE_USER")));
        
        if (requestMap != null){
            for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
                RequestMatcher matcher = entry.getKey();
                if (matcher.matches(request)){
                    return entry.getValue(); // 권한정보 리턴
                }
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    /**
     * reload를 통해 실시간 인가정보 업데이트
     * 호출 메소드
     * {@link com.example.corespringsecurity.controller.admin.ResourcesController}
     *  createResources
     *  removeResources
     */
    public void reload(){

        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();

        requestMap.clear();

        while(iterator.hasNext()) {
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(), entry.getValue());
        }
    }
}