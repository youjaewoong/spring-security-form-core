package com.example.corespringsecurity.security.listener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.example.corespringsecurity.domain.entity.AccessIp;
import com.example.corespringsecurity.domain.entity.Account;
import com.example.corespringsecurity.domain.entity.Resources;
import com.example.corespringsecurity.domain.entity.Role;
import com.example.corespringsecurity.domain.entity.RoleHierarchy;
import com.example.corespringsecurity.repository.AccessIpRepository;
import com.example.corespringsecurity.repository.ResourcesRepository;
import com.example.corespringsecurity.repository.RoleHierarchyRepository;
import com.example.corespringsecurity.repository.RoleRepository;
import com.example.corespringsecurity.repository.UserRepository;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private boolean alreadySetup = false;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private ResourcesRepository resourcesRepository;

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AccessIpRepository accessIpRepository;

    private static AtomicInteger count = new AtomicInteger(0);

    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {

        if (alreadySetup) {
            return;
        }

        setupSecurityResources();

        setupAccessIpData();

        alreadySetup = true;
    }

    private void setupSecurityResources() {

        //createResourceIfNotFound("execution(public * com.example.corespringsecurity.aopsecurity.*Service.pointcut*(..))", "", roles, "pointcut");
    	 
        
        Set<Role> userRoles = new HashSet<>();
        Role userRole = createRoleIfNotFound("ROLE_USER", "사용자권한");
        userRoles.add(userRole);
        createUserIfNotFound("user", "user@user.com", "1111", userRoles);
        createResourceIfNotFound("/mypage", "", userRoles, "url");
        createResourceIfNotFound("com.example.corespringsecurity.aopsecurity.AopMethodService.methodSecured", "", userRoles, "method");
        createResourceIfNotFound("com.example.corespringsecurity.aopsecurity.AopLiveMethodService.liveMethodSecured", "", userRoles, "method");
        
        Set<Role> managerRoles = new HashSet<>();
        Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저권한");
        managerRoles.add(managerRole);
        createResourceIfNotFound("/messages", "", managerRoles, "url");
        createResourceIfNotFound("/config", "", managerRoles, "url");
        createUserIfNotFound("manager", "manager@manager.com", "1111", managerRoles);
        
        
        Set<Role> roles = new HashSet<>();
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자"); // 롤등록
        roles.add(adminRole);
        createResourceIfNotFound("/admin/**", "", roles, "url"); // 리소스관리 등록
        createUserIfNotFound("admin", "admin@admin.com", "1111", roles);  // 관리자 등록
        
        // RoleHierarchy 등록
        createRoleHierarchyIfNotFound(managerRole, adminRole);
        createRoleHierarchyIfNotFound(userRole, managerRole);
    }

    @Transactional
    public Role createRoleIfNotFound(String roleName, String roleDesc) {

        Role role = roleRepository.findByRoleName(roleName);

        if (role == null) {
            role = Role.builder()
                    .roleName(roleName)
                    .roleDesc(roleDesc)
                    .build();
        }
        return roleRepository.save(role);
    }

    @Transactional
    public Account createUserIfNotFound(final String userName, final String email, final String password, Set<Role> roleSet) {

        Account account = userRepository.findByUsername(userName);

        if (account == null) {
            account = Account.builder()
                    .username(userName)
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roleSet)
                    .build();
        }
        return userRepository.save(account);
    }

    @Transactional
    public Resources createResourceIfNotFound(String resourceName, String httpMethod, Set<Role> roleSet, String resourceType) {
        Resources resources = resourcesRepository.findByResourceNameAndHttpMethod(resourceName, httpMethod);

        if (resources == null) {
            resources = Resources.builder()
                    .resourceName(resourceName)
                    .roleSet(roleSet)
                    .httpMethod(httpMethod)
                    .resourceType(resourceType)
                    .orderNum(count.incrementAndGet())
                    .build();
        }
        return resourcesRepository.save(resources);
    }

    @Transactional
    public void createRoleHierarchyIfNotFound(Role childRole, Role parentRole) {

        RoleHierarchy roleHierarchy = roleHierarchyRepository.findByChildName(parentRole.getRoleName());
        if (roleHierarchy == null) {
            roleHierarchy = RoleHierarchy.builder()
                    .childName(parentRole.getRoleName())
                    .build();
        }
        RoleHierarchy parentRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);

        roleHierarchy = roleHierarchyRepository.findByChildName(childRole.getRoleName());
        if (roleHierarchy == null) {
            roleHierarchy = RoleHierarchy.builder()
                    .childName(childRole.getRoleName())
                    .build();
        }

        RoleHierarchy childRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);
        childRoleHierarchy.setParentName(parentRoleHierarchy);
    }

    private void setupAccessIpData() {
    	String ips[] = {"0:0:0:0:0:0:0:1", "127.0.0.1"};
    	for (int i = 0; i < ips.length; i++) {
            AccessIp byIpAddress = accessIpRepository.findByIpAddress(ips[i]);
            if (byIpAddress == null) {
                AccessIp accessIp = AccessIp.builder()
                        .ipAddress(ips[i])
                        .build();
                accessIpRepository.save(accessIp);
            }
		}

    }
}
