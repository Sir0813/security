package com.spring.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录失败逻辑处理
 */
@Component
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException exception) throws IOException, ServletException {
        log.info("登陆失败{}" + exception.getMessage());
        httpServletResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        httpServletResponse.setContentType("application/json;charset=UTF-8");
        expetionToWriter(httpServletResponse, exception);
    }

    private static void expetionToWriter(HttpServletResponse httpServletResponse, AuthenticationException exception) throws IOException {
        if (exception instanceof UsernameNotFoundException) {
            httpServletResponse.getWriter().write("用户不存在!!!");
        } else if (exception instanceof BadCredentialsException) {
            httpServletResponse.getWriter().write("密码错误!!!");
        } else if (exception instanceof DisabledException) {
            httpServletResponse.getWriter().write("用户已被禁用!!!");
        } else if (exception instanceof LockedException) {
            httpServletResponse.getWriter().write("账户锁定!!!");
        } else if (exception instanceof AccountExpiredException) {
            httpServletResponse.getWriter().write("账户过期!!!");
        } else if (exception instanceof CredentialsExpiredException) {
            httpServletResponse.getWriter().write("证书过期!!!");
        } else {
            httpServletResponse.getWriter().write(exception.toString());
        }
    }
}
