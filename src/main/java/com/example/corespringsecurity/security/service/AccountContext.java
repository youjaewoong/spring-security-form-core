package com.example.corespringsecurity.security.service;

import com.example.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

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
