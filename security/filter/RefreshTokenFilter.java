package org.daewon.phreview.security.filter;

import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.daewon.phreview.security.exception.RefreshTokenException;
import org.daewon.phreview.utils.JWTUtil;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final String refreshToken;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        log.info("path: " + path);

        // url주소에 /refreshToken이 없으면 refresh Token filter를 skip
        if(!path.contains("refreshToken")) {
            log.info("리프레시 토큰 필터를 스킵합니다..........");
            filterChain.doFilter(request, response);
            return;
        }

        log.info("리프레시 토큰 필터..........실행......");

        // 전송된 JSON에서 accessToken과 refreshToken을 얻어온다
        Map<String, String> tokens = parseRequstJSON(request);

        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken : " + accessToken);
        log.info("refreshToken : " + refreshToken);

        // accessToken 관련 exception
        try {
            checkAccessToken(accessToken);
        } catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return;
        }

        Map<String, Object> refreshClaims = null;
        // refreshToken 관련 exception

        try {
            refreshClaims = checkRefreshToken(refreshToken);
            log.info(refreshClaims);

            // 새로운 Access Token 발행
            // Refrsh Token은 만료일이 얼마 남지 않은 경우 새로 발행

            // Refresh Token의 유효 시간이 얼마 남지 않은 경우
            Long exp = (Long) refreshClaims.get("exp");
            Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);   // 만료 시간
            Date current = new Date(System.currentTimeMillis());                        // 현재 시간

            // 만료 시간과 현재 시간의 간격 계산
            // 만일 3일 미만인 경우에는 Refresh Token도 다시 생성
            long gapTime = (expTime.getTime() - current.getTime());     // 토큰 유효기간 남은 시간

            log.info("------------------------------");
            log.info("현재 시간 : " + current);
            log.info("만료 시간 : " + expTime);
            log.info("토큰 유효기간 남은 시간 : " + gapTime);

            String email = (String) refreshClaims.get("email");

            // 이 상태까지 오면 무조건 AccessToken은 새로 생성
            String accessTokenValue = jwtUtil.generateToken(Map.of("email", email), 1);
            String refreshTokenValue = tokens.get("refreshToken");

            // RefreshToken이 3일도 안 남았다면
            if(gapTime < (1000 * 60 * 60 * 24 * 3)) {
                log.info("새로운 Refresh Token이 필요합니다......");
                refreshTokenValue = jwtUtil.generateToken(Map.of("email", email), 30);
            }

            log.info("Refresh Token 결과.......................");
            log.info("accessToken: " + accessTokenValue);
            log.info("refreshToken: " + refreshTokenValue);

            // 새로운 토큰들을 생성한 후 sendTokens()를 호출
            sendTokens(accessTokenValue, refreshTokenValue, response);

        } catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return;
        }
    }

    private Map<String, String> parseRequstJSON(HttpServletRequest request) {

        // JSON 데이터를 분석해서 email, password 전달 값을 Map으로 처리
        try(Reader reader = new InputStreamReader(request.getInputStream())) {
            Gson gson = new Gson();

            return gson.fromJson(reader, Map.class);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    // accessToken 검증
    private void checkAccessToken(String accessToken) throws RefreshTokenException {
        try {
            jwtUtil.validateToken(accessToken);
        } catch (ExpiredJwtException expiredJwtException) { // 만료 기간이 지났을 때
            log.info("Access Token이 만료되었습니다");
        } catch (Exception exception) {     // 나머지 상황
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }

    // refreshToken 검증
    // refreshToken이 존재하는지와 만료이 지났는지 확인, 새로운 토큰 생성을 위해 email 값을 얻어 둠
    private Map<String, Object> checkRefreshToken(String refreshToken) throws RefreshTokenException {
        try {
            Map<String, Object> values = jwtUtil.validateToken(refreshToken);
            return values;
        } catch (ExpiredJwtException expiredJwtException) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        } catch (MalformedJwtException malformedJwtException) {
            log.error("잘못된 형식의 Refresh Token입니다-----------------------");
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        } catch (Exception exception) {
            new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
        return null;
    }

    // 만들어진 토큰들을 전송하는 sendTokens()
    private void sendTokens(String accessTokenValue, String refreshTokenValue, HttpServletResponse response) {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();
        String jsonStr = gson.toJson(Map.of("accessToken", accessTokenValue, "refreshToken", refreshTokenValue));

        try {
            response.getWriter().println(jsonStr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}