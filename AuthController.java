package org.daewon.phreview.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.daewon.phreview.domain.RefreshToken;
import org.daewon.phreview.domain.Users;
import org.daewon.phreview.dto.auth.AuthSigninDTO;
import org.daewon.phreview.dto.auth.AuthSignupDTO;
import org.daewon.phreview.repository.RefreshTokenRepository;
import org.daewon.phreview.security.UsersDetailsService;
import org.daewon.phreview.service.AuthService;
import org.daewon.phreview.utils.JWTUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


@Log4j2
@RequestMapping("/auth")
@RequiredArgsConstructor
@RestController
@EnableWebSecurity
public class AuthController {

    private final JWTUtil jwtUtil;
    private final AuthService authService;
    private final UsersDetailsService usersDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;

    @GetMapping("/signup")
    public void signupGET() {
        log.info("join get");
    }

    @Operation(summary = "회원가입 처리", description = "회원가입 요청을 처리합니다.")
    @PostMapping("/signup")
    public Users signup(@RequestBody AuthSignupDTO authSignupDTO) {
        log.info("signup post.....");
        log.info(authSignupDTO);

        try {
            Users user = authService.signup(authSignupDTO);

            log.info(user);

            return user;
        } catch (AuthService.UserEmailExistException e) {
            log.error("Email already exists: " + authSignupDTO.getEmail(), e);
        }

        return null;
    }

    @GetMapping("/signin")
    public void signinGET(String error, String logout) {
        log.info("signin get..................");
        log.info("logout : "+logout);

        if(logout != null) {
            log.info("user logout....");
        }
    }

    @Operation(summary = "로그인 처리", description = "로그인 요청을 처리합니다.")
    @RequestMapping(value = "/signin", method = RequestMethod.POST)
    public ResponseEntity<?> signin(@RequestBody AuthSigninDTO dto) {
        log.info(dto.getEmail());

        // AuthService를 사용하여 사용자의 인증을 시도
        Users users = authService.signin(
                dto.getEmail(),
                dto.getPassword());

        // 사용자가 존재하는 경우
        if (users != null) {
            // 사용자의 이메일을 기반으로 UserDetails를 가져옴
            UserDetails userDetails = usersDetailsService.loadUserByUsername(dto.getEmail());

            // 토큰 생성
            // UsernamePasswordAuthenticationToken, UserId=Principal, Password=Credential 역할을 함
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());

            // SecurityContextHolder에 인증을 설정
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            // JWT Payload에 userId, userName, email, roles 값을 실어서 보냄
            Map<String, Object> claim = new HashMap<>();
            claim.put("userId", users.getUserId());
            claim.put("userName", users.getUserName());
            claim.put("email", users.getEmail());
            claim.put("roles", userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));

            String accessToken = jwtUtil.generateToken(claim, 1);
            String refreshToken = jwtUtil.generateToken(claim, 30);

            // Refresh Token을 DB에 저장
            RefreshToken newToken = new RefreshToken();
            newToken.setToken(refreshToken);
            newToken.setEmail(userDetails.getUsername());
            refreshTokenRepository.save(newToken);

            Map<String, String> tokens = Map.of("accessToken", accessToken, "refreshToken", refreshToken);

            // ok()에 클라이언트에게 반환할 토큰을 포함
            // ResponseEntity나 @ResponseBody 어노테이션을 사용하면 스프링은 기본적으로 데이터를 JSON 형식으로 변환하여 클라이언트에게 응답함.
            // 결론은 클라이언트는 JSON 형식으로 데이터를 받게 됨
            return ResponseEntity.ok(tokens);
        }else {
            // 401에러 발생
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
        }


    }
}