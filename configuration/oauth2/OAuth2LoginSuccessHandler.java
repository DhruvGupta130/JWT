package com.trulydesignfirm.emenu.configuration.oauth2;

import com.trulydesignfirm.emenu.configuration.JwtUtils;
import com.trulydesignfirm.emenu.enums.Role;
import com.trulydesignfirm.emenu.model.LoginUser;
import com.trulydesignfirm.emenu.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    private final UserRepo userRepo;

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
            newUser.setRole(Role.OWNER);
            userRepo.save(newUser);
            userDetails = userDetailsService.loadUserByUsername(email);
        }
        String jwtToken = jwtUtils.generateToken(userDetails);
        response.sendRedirect(frontendUrl+"/oauth-success?token=" + jwtToken);
    }
}