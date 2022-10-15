package com.example.corespringsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.corespringsecurity.domain.entity.AccessIp;

public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {

    AccessIp findByIpAddress(String IpAddress);
}
