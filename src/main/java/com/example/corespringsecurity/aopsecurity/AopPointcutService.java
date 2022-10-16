package com.example.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

@Service
public class AopPointcutService {

	// pointcut 대상
    public void pointcutSecured(){
        System.out.println("pointcutSecured");
    }

    public void notSecured(){
        System.out.println("notSecured");
    }
}
