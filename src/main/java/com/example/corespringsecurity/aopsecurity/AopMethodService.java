package com.example.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

/**
 * 권한이 있으면 접근 가능
 */
@Service
public class AopMethodService {

    public void methodSecured() {
        System.out.println("methodSecured");
    }
}
