package com.example.corespringsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.corespringsecurity.domain.entity.RoleHierarchy;

public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

    RoleHierarchy findByChildName(String roleName);
}
