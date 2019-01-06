package com.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@ComponentScan(basePackages = "com.test")
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("nidish").password(passwordEncoder().encode("nidish123"))
			.authorities("ROLE_USER");
	}
	
	

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/SpringMVC/").permitAll()
		.antMatchers("/SpringMVC/greet/*").access("hasRole('ROLE_USER')")
		.anyRequest().authenticated()
			.and()
			.formLogin()
			.loginPage("/login.jsp")
			.defaultSuccessUrl("/home.jsp")
			.failureUrl("/login.jsp")
			  .usernameParameter("username").passwordParameter("password")
	        .and().csrf()
			.and()
			.logout().logoutSuccessUrl("/login.jsp");
	}
	
	


	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}

	
//	
//	 @Autowired
//	    public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
//	        auth.inMemoryAuthentication().withUser("bill").password("abc123").roles("USER");
//	        auth.inMemoryAuthentication().withUser("admin").password("root123").roles("ADMIN");
//	        auth.inMemoryAuthentication().withUser("dba").password("root123").roles("ADMIN","DBA");
//	    }
//	     
//	    @Override
//	    protected void configure(HttpSecurity http) throws Exception {
//	       
//	      http.authorizeRequests()
//	        .antMatchers("/", "/login").permitAll()
//	        .antMatchers("/greet/**").access("hasRole('ADMIN')")
//	        .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
//	        .and().formLogin().loginPage("/login")
//	        .usernameParameter("username").passwordParameter("password")
//	        .and().csrf()
//	        .and().exceptionHandling().accessDeniedPage("/login");
//	    }
}
