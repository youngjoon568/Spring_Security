package org.daewon.phreview.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

@Log4j2
public class Custom403Handler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.info("--------------------- 접근 거부 -----------------------------");

        response.setStatus(HttpStatus.FORBIDDEN.value());

        String contentType = request.getHeader("Content-Type");
        boolean jsonRequest = contentType != null && contentType.startsWith("application/json");
        log.info("JSON 요청인가? " + jsonRequest);

        if (!jsonRequest) {
            response.sendRedirect("/user/login?error=ACCESS_DENIED");
        }
    }
}