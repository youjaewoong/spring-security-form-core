package com.example.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

/**
 * MethodSecurityInterceptor 에서 인가처리
 */
@Service
public class AopLiveMethodService {

    public void liveMethodSecured(){

        System.out.println("liveMethodSecured");
    }
}
