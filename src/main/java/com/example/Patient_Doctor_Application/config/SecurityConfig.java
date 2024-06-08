package com.example.Patient_Doctor_Application.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

//    private final UserDetailsService userDetailsService;
//    private final PasswordEncoder passwordEncoder;
//
//
//
//    public SecurityConfig(CustomUserDetailsService userDetailsService) {
//        this.userDetailsService = userDetailsService;
//        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }



    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/", "/**","/errorPage").permitAll() // Allow access to these paths without authentication
                                .requestMatchers("/doctorHome").hasRole("DOCTOR")
                        //.anyRequest().authenticated() // Require authentication for all other paths
                )
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/docLogin") // Specify custom login page URL
                                .permitAll() // Allow access to login page without authentication
                )
                .logout(logout ->
                        logout
                                .logoutUrl("/logout") // Specify custom logout URL
                                .logoutSuccessUrl("/") // Redirect to login page after logout
                                .permitAll() // Allow access to logout URL without authentication
                )
                .authenticationProvider(authenticationProvider())
                .csrf().disable(); // Disable CSRF protection for simplicity
        return http.build();
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests(authorizeRequests ->
//                        authorizeRequests
//                                // Allow access to /userRegister, /newPatient, /appointmentRegister/**, /appointment
//                                .requestMatchers("/userRegister", "/newPatient", "/appointmentRegister/**", "/appointment").hasAnyRole("USER", "DOCTOR")
//                                // Allow access to /doctorHome, /updateDoc/**, /updateDoctor, /saveComment
//                                .requestMatchers("/doctorHome", "/updateDoc/**", "/updateDoctor", "/saveComment").hasRole("DOCTOR")
//                                // Allow access to all endpoints for authenticated users
//                                .anyRequest().authenticated()
//                )
//                .formLogin()
//                .loginPage("/docLogin") // Custom login page
//                .permitAll()
//                .and()
//                .logout()
//                .permitAll()
//                .and()
//                .csrf().disable();
//        return http.build();
//    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return new ProviderManager(Arrays.asList(authenticationProvider()));
    }
}