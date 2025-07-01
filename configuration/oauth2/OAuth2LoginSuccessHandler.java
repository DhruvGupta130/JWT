package com.trulydesignfirm.emenu.configuration.oauth2;

import com.trulydesignfirm.tfsc.configuration.JwtCookieProperties;
import com.trulydesignfirm.tfsc.configuration.JwtUtils;
import com.trulydesignfirm.tfsc.enums.Role;
import com.trulydesignfirm.tfsc.model.LoginUser;
import com.trulydesignfirm.tfsc.repository.LoginUserRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    private final LoginUserRepo loginUserRepo;
    private final JwtCookieProperties jwtCookieProperties;

    @Value("${frontend_url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(email);
        } catch (UsernameNotFoundException e) {
            LoginUser newUser = new LoginUser();
            newUser.setEmail(email);
            newUser.setPassword(UUID.randomUUID().toString());
            newUser.setName(name);
            newUser.setRole(Role.USER);
            loginUserRepo.save(newUser);
            userDetails = userDetailsService.loadUserByUsername(email);
        }
        String token = jwtUtils.generateToken(userDetails);
        ResponseCookie jwtCookie = ResponseCookie.from(jwtCookieProperties.getName(), token)
                .httpOnly(jwtCookieProperties.isHttpOnly())
                .secure(jwtCookieProperties.isSecure())
                .sameSite(jwtCookieProperties.getSameSite())
                .path(jwtCookieProperties.getPath())
                .maxAge(jwtCookieProperties.getMaxAge())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.sendRedirect(frontendUrl + "/oauth-success");
    }
}