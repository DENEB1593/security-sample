package config;

import controller.handler.CustomLoginSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인코딩필터 등록
        CharacterEncodingFilter encodingFilter = new CharacterEncodingFilter();
        encodingFilter.setEncoding("UTF-8");
        encodingFilter.setForceEncoding(true);
        http.addFilterBefore(encodingFilter, CsrfFilter.class);

        // 접근 설정
        http.authorizeRequests()
                .antMatchers("/login/all").permitAll()
                .antMatchers("/login/admin").access("hasRole('ROLE_ADMIN')")
                .antMatchers("/login/member").access("hasRole('ROLE_MEMBER')");
        
        // 로그인 처리
        http.formLogin()
                .loginPage("/customLogin")
                .loginProcessingUrl("/login")
                .successHandler(loginSuccessHandler());

        // 로그아웃 처리
        http.logout()
                .logoutUrl("customLogout")
                .invalidateHttpSession(true)
                .deleteCookies("remember-me", "JSESSION-ID");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        log.info("configure...........");
        auth.inMemoryAuthentication()
                .withUser("admin").password("{noop}admin").roles("ADMIN");

        auth.inMemoryAuthentication()
                .withUser("member").password("$2a$10$2W4JV99GGYlD250Wpv2J4Oyxzwu8lbKvdKbuDTB3Cri2UW4Nc5nma").roles("MEMBER");
    }

    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler() {
        return new CustomLoginSuccessHandler();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
