package com.example.ss_2022_c6_e1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        var uds = new InMemoryUserDetailsManager();

        var u1 = User.withUsername("bill")
                .password(passwordEncoder().encode("12345"))
                .authorities("read") // --> GrantedAuthority Interface
                .build();

        var u2 = User.withUsername("john")
                .password(passwordEncoder().encode("12345"))
                .authorities("write") // -->
                .build();

        uds.createUser(u1);
        uds.createUser(u2);

        return uds;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.httpBasic()
                .and()
//                .authorizeRequests(c -> c.anyRequest().authenticated())
                .authorizeRequests()
//                .mvcMatchers(HttpMethod.GET, "/demo/**").hasAuthority("read") /// find ANT expressions  /**
                .mvcMatchers("/test/test1").authenticated()
//                .regexMatchers("regex").authenticated()
                .anyRequest().permitAll()
                .and().csrf().disable() // Don't do this in real world apps
//                .mvcMatchers("/test2").hasAuthority("read")
                .build();
    }

    // /demo/anything/*/something ---> /demo/anything/abc/something
    //                                 /demo/anything/xyz/something

}
