package org.daewon.phreview.security.filter;

import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

@Log4j2
public class LoginFilter extends AbstractAuthenticationProcessingFilter {

    public LoginFilter(String defaultFilterProcessUrl) {
        super(defaultFilterProcessUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        log.info("로그인 필터 실행...............");

        if (request.getMethod().equalsIgnoreCase("GET")) {
            log.info("GET 메서드는 지원하지 않습니다");
            return null;
        }

        Map<String, String> jsonData = parseRequestJSON(request);

        log.info("전송된 JSON 데이터 : " + jsonData);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                jsonData.get("email"),
                jsonData.get("password")
        );

        if (jsonData.get("email") == null || jsonData.get("email").isEmpty()) {
            throw new AuthenticationServiceException("이메일이 입력되지 않았습니다");
        }
        if (jsonData.get("password") == null || jsonData.get("password").isEmpty()) {
            throw new AuthenticationServiceException("비밀번호가 입력되지 않았습니다");
        }

        log.info("생성된 authenticationToken : " + authenticationToken.getPrincipal().toString());

        return getAuthenticationManager().authenticate(authenticationToken);
    }

    private Map<String, String> parseRequestJSON(HttpServletRequest request) {
        try (Reader reader = new InputStreamReader(request.getInputStream())) {
            Gson gson = new Gson();
            return gson.fromJson(reader, Map.class);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }
}