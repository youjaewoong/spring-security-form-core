package com.example.corespringsecurity.service;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import com.example.corespringsecurity.domain.entity.Resources;
import com.example.corespringsecurity.repository.AccessIpRepository;
import com.example.corespringsecurity.repository.ResourcesRepository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SecurityResourceService {

	private ResourcesRepository resourcesRepository;
	private AccessIpRepository accessIpRepository;

	public SecurityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
		this.resourcesRepository = resourcesRepository;
		this.accessIpRepository = accessIpRepository;
	}

	
	// url방식 권한 및 자원 정보 호출
	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resourcesList = resourcesRepository.findAllResources();
		resourcesList.forEach(re -> {
			List<ConfigAttribute> configAttributeList = new ArrayList<>();
			re.getRoleSet().forEach(role -> {
				configAttributeList.add(new SecurityConfig(role.getRoleName()));
			});
			result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributeList);

		});
		return result;
	}

	
	// method 방식 권한 및 자원 정보 호출
	public LinkedHashMap<String, List<ConfigAttribute>> getMethodResourceList() {

		LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resourcesList = resourcesRepository.findAllMethodResources();
		resourcesList.forEach(re -> {
			List<ConfigAttribute> configAttributeList = new ArrayList<>();
			re.getRoleSet().forEach(ro -> {
				configAttributeList.add(new SecurityConfig(ro.getRoleName()));
			});
			result.put(re.getResourceName(), configAttributeList);
		});
		return result;
	}

	// pointcut 방식 권한 및 자원 정보 호출
	public LinkedHashMap<String, List<ConfigAttribute>> getPointcutResourceList() {

		LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resourcesList = resourcesRepository.findAllPointcutResources();
		resourcesList.forEach(re -> {
			List<ConfigAttribute> configAttributeList = new ArrayList<>();
			re.getRoleSet().forEach(ro -> {
				configAttributeList.add(new SecurityConfig(ro.getRoleName()));
			});
			result.put(re.getResourceName(), configAttributeList);
		});
		return result;
	}

	
	public List<String> getAccessIpList() {
		List<String> accessIpList = accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress())
				.collect(Collectors.toList());
		return accessIpList;
	}
}
