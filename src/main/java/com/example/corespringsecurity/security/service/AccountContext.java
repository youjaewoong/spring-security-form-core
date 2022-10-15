package com.example.corespringsecurity.security.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.example.corespringsecurity.domain.entity.Account;

import java.util.Collection;

public class AccountContext extends User {

	private static final long serialVersionUID = -4109485886128135913L;
	private final Account account;

    public Account getAccount() {
        return account;
    }

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {

        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;

    }

}
