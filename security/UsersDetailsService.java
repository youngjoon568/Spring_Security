package org.daewon.phreview.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.daewon.phreview.domain.Users;
import org.daewon.phreview.dto.auth.AuthSigninDTO;
import org.daewon.phreview.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

// Spring Security에서 사용자 인증을 처리하기 위해 UserDetailsService 인터페이스를 구현한 서비스 클래스
@Service
@Log4j2
@RequiredArgsConstructor
public class UsersDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // 이메일을 기반으로 사용자 정보를 로드하는 메서드
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("loadUserByUsername : " + email);

        // 이메일을 사용하여 사용자 조회
        Optional<Users> result = userRepository.findByEmail(email);
        log.info("result : " + result);

        if (!result.isPresent()) {
            throw new UsernameNotFoundException("이메일로 사용자를 찾을 수 없습니다 : " + email);
        }

        Users user = result.get(); // Optional에서 사용자 객체를 추출

        log.info("사용자를 찾았습니다: " + user);

        // 사용자에게 할당된 역할이 비어 있는지 확인
        if (user.getRoleSet().isEmpty()) {
            log.error("사용자에게 할당된 역할이 없습니다");
            throw new UsernameNotFoundException("사용자에게 할당된 역할이 없습니다");
        }

        // 권한을 SimpleGrantedAuthority로 변환
        List<SimpleGrantedAuthority> authorities;
        try {
            authorities = user.getRoleSet().stream()
                    .peek(role -> log.info("사용자의 권한: ROLE_" + role))
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("역할을 권한으로 변환하는 중 오류가 발생했습니다", e);
            throw new UsernameNotFoundException("역할을 권한으로 변환할 수 없습니다", e);
        }

        // AuthSigninDTO 객체 생성 및 반환
        return new AuthSigninDTO(
                user.getUserName(),
                user.getPassword(),
                user.getEmail(),
                authorities,
                user.getUserId());
    }
}