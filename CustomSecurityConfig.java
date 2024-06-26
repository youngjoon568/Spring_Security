package org.daewon.phreview.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.daewon.phreview.security.UsersDetailsService;
import org.daewon.phreview.security.filter.CustomSecurityConfig.java;
import org.daewon.phreview.security.filter.TokenCheckFilter;
import org.daewon.phreview.security.handler.Custom403Handler;
import org.daewon.phreview.utils.JWTUtil;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
@Log4j2
@EnableMethodSecurity
@RequiredArgsConstructor
@EnableWebSecurity
public class CustomSecurityConfig {

    private final UsersDetailsService usersDetailsServicea;
    private final JWTUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("------------------------- web configure ------------------------------");

        // 정적 리소스 필터링 제외
        return (web) -> web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http, UsersDetailsService usersDetailsService) throws Exception {
        log.info("------------------------ configure ----------------------------------");

        // AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(usersDetailsServicea)
                .passwordEncoder(passwordEncoder());

        // Get AuthenticationManager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        // 인증 매니저 등록...
        http.authenticationManager(authenticationManager);

//        // LoginFilter 설정....
//        LoginFilter loginFilter = new LoginFilter("/generateToken");
//        loginFilter.setAuthenticationManager(authenticationManager);

//        // APILoginSuccessHandler
//        // JWTUtil에서 토큰을 생성하고 successHandler에서 JSON값으로 변환
//        UserLoginSuccessHandler successHandler = new UserLoginSuccessHandler(jwtUtil);
//        // SuccessHandler 설정
//        loginFilter.setAuthenticationSuccessHandler(successHandler);
//
//        // APILoginFilter의 위치 조정 - UsernamePaswwordAuthenctionFilter이전에 동작해야 하는 필터이기 때문..
//        http.addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class);

        // /api로 시작하는 모든 경로는 TokenCheckFilter 동작
        http.addFilterBefore(
                tokenCheckFilter(jwtUtil, usersDetailsServicea),
                UsernamePasswordAuthenticationFilter.class
        );

        // refreshToken 호출 처리
        http.addFilterBefore(new RefreshTokenFilter("/refreshToken", jwtUtil), TokenCheckFilter.class);

        // CSRF 토큰 비활성화
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());
        // 세션 비활성화
        http.sessionManagement(httpSecuritySessionManagementConfigurer ->
                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                ));

        // cors 설정
        http.cors(httpSecurityCorsConfigurer -> {
            httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());
        });

        return http.build();
    }

    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil, UsersDetailsService usersDetailsServicea) {
        return new TokenCheckFilter(jwtUtil, usersDetailsServicea);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new Custom403Handler();
    }

    // cors
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        // 접근할 URL을 지정하여 처리... "*" 는 모든 주소로의 접근 허용. 대상 지정하면 지정 대상만 접근 가능...
        corsConfiguration.setAllowedOriginPatterns(Arrays.asList("http://localhost:3000"));
        corsConfiguration.setAllowedMethods(Arrays.asList("HEAD","GET","POST","PUT","DELETE"));
        corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization","Cache-Control","Content-Type"));
        corsConfiguration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);  // "/**" - 하위 모든 폴더.....
        return source;
    }

    // refreshTokenFilter 설정
    @Bean
    public FilterRegistrationBean<RefreshTokenFilter> refreshTokenFilter() {
        FilterRegistrationBean<RefreshTokenFilter> filterRegistrationBean = new FilterRegistrationBean<>();

        filterRegistrationBean.setFilter(new RefreshTokenFilter("/refreshToken", jwtUtil));
        // 'api/*' 패턴의 모든 요청에 refreshToken Filter 적용
        filterRegistrationBean.addUrlPatterns("/api/*");

        return filterRegistrationBean;
    }

}
