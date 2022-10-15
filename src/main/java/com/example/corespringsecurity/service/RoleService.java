package com.example.corespringsecurity.service;


import java.util.List;

import com.example.corespringsecurity.domain.entity.Role;

public interface RoleService {

    Role getRole(long id);

    List<Role> getRoles();

    void createRole(Role role);

    void deleteRole(long id);
}