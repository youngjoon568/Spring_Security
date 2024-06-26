package org.daewon.phreview.security.handler;

import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.daewon.phreview.dto.auth.AuthSecurityDTO;
import org.daewon.phreview.utils.JWTUtil;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Log4j2
@RequiredArgsConstructor
public class UserLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("로그인 성공 핸들러.............");

        // 응답 콘텐츠 타입을 JSON으로 설정
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        log.info(authentication.toString());
        log.info("사용자 이름: " + authentication.getName()); // username

        String email = ((AuthSecurityDTO) authentication.getPrincipal()).getEmail();
        log.info("이메일: " + email);
        AuthSecurityDTO authSecurityDTO = (AuthSecurityDTO) authentication.getPrincipal();
        Long userId = authSecurityDTO.getUserId();
        log.info("사용자 ID: " + userId);

        // 클레임 생성 : JWT 토큰에 포함될 클레임(사용자 정보)을 생성
        Map<String, Object> claim = new HashMap<>();
        claim.put("userId", userId);
        claim.put("email", email);
        claim.put("roles", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        // Access Token 유효기간 1일
        String accessToken = jwtUtil.generateToken(claim, 1);
        // Refresh Token 유효기간 30일
        String refreshToken = jwtUtil.generateToken(claim, 30);

        // accessToken, refreshToken을 포함한 JSON 응답 생성
        Gson gson = new Gson();
        Map<String, String> keyMap = Map.of("accessToken", accessToken, "refreshToken", refreshToken);

        String jsonStr = gson.toJson(keyMap);

        // JSON 응답을 출력에 작성
        response.getWriter().println(jsonStr);
    }
}