package com.example.corespringsecurity.security.config;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import com.example.corespringsecurity.security.factory.MethodResourcesMapFactoryBean;
import com.example.corespringsecurity.security.interceptor.CustomMethodSecurityInterceptor;
import com.example.corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import com.example.corespringsecurity.service.SecurityResourceService;

/**
 * map 기반 method 보안처리 GlobalMethodSecurityConfiguration 는 메소드보안 관련 초기화및 인가처리
 * 담당을한다. GlobalMethodSecurityConfiguration 의 MethodSecurityMetadataSource
 * customMethodSecurityMetadataSource 의 구현체 처리를한다.
 */
@Configuration
@EnableGlobalMethodSecurity
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	@Autowired
	private SecurityResourceService securityResourceService;

	@Override
	protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
		return mapBasedMethodSecurityMetadataSource();
	}
	
	// ********************************** 메소드 보안 START **************************************
	// MethodSecurityMetadataSource 기반의 custom 처리 방식
	@Bean
	public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
		return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
	}

	
	/**
	 * FactoryBean 구현한 MethodResourcesMapFactoryBean > attemptMatch 에서 매칭된 자원을
	 * mapBasedMethodSecurityMetadataSource로 보낸
	 * 
	 * method type
	 */
	@Bean
	public MethodResourcesMapFactoryBean methodResourcesMapFactoryBean() {
		MethodResourcesMapFactoryBean methodResourcesMapFactoryBean = new MethodResourcesMapFactoryBean();
		methodResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		methodResourcesMapFactoryBean.setResourceType("method");
		return methodResourcesMapFactoryBean;
	}
	// ********************************** 메소드 보안 END  **************************************
	
	// ********************************** 포인트컷 보안 START  **************************************
	/**
	 * DB로부터 pointcut 데이터를 가져온다.
	 */
	@Bean
	// @Profile("pointcut")
	public MethodResourcesMapFactoryBean pointcutResourcesMapFactoryBean() {
		MethodResourcesMapFactoryBean methodResourcesMapFactoryBean = new MethodResourcesMapFactoryBean();
		methodResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		methodResourcesMapFactoryBean.setResourceType("pointcut");
		return methodResourcesMapFactoryBean;
	}
	

	/**
	 * ProtectPointcutPostProcessor 에서 bean 검사 및 주입
	 */
	@Bean
	// @Profile("pointcut")
	public ProtectPointcutPostProcessor protectPointcutPostProcessor() {
		ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(
				mapBasedMethodSecurityMetadataSource());
		protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());
		return protectPointcutPostProcessor;
	}

	
	/**
	 * 실시간 메소드보안
	 */
	@Bean
	public CustomMethodSecurityInterceptor customMethodSecurityInterceptor(
			MapBasedMethodSecurityMetadataSource methodSecurityMetadataSource) {
		CustomMethodSecurityInterceptor customMethodSecurityInterceptor = new CustomMethodSecurityInterceptor();
		customMethodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		customMethodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
		
		// methodSecurityMetadataSource 셋팅하기위해서 CustomMethodSecurityInterceptor 만들어 처리
		customMethodSecurityInterceptor.setSecurityMetadataSource(methodSecurityMetadataSource);
		RunAsManager runAsManager = runAsManager();
		if (runAsManager != null) {
			customMethodSecurityInterceptor.setRunAsManager(runAsManager);
		}

		return customMethodSecurityInterceptor;
	}
	

//    @Bean
//    @Profile("pointcut")
//    BeanPostProcessor protectPointcutPostProcessor() throws Exception {
//
//        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor");
//        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
//        declaredConstructor.setAccessible(true);
//        Object instance = declaredConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
//        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
//        setPointcutMap.setAccessible(true);
//        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());
//
//        return (BeanPostProcessor)instance;
//    }

	// ********************************** 포인트컷 보안 END  **************************************
}
