package com.spring.security.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@Slf4j
public class LoginController {

    /**
     * 获取当前登录用户：SecurityContextHolder.getContext().getAuthentication()
     * @PreAuthorize 用于判断用户是否有指定权限，没有就不能访问
     */
    @RequestMapping("/")
    public String showHome() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("当前登陆用户：" + name);
        return "home.html";
    }

    @RequestMapping("/login")
    public String showLogin() {
        return "login.html";
    }

    @RequestMapping("/admin")
    @ResponseBody
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String printAdmin() {
        return "如果你看见这句话，说明你有read权限";
    }

    /**
     * hasRole() 必须有某个角色权限才能访问
     * hasPermission() 必须有某个url的某个操作权限才能访问
     * 如果配置了 角色继承 如 admin>user 则admin可以访问user所有角色内容
     * @return
     */
    @RequestMapping("/admin/c")
    @ResponseBody
//    @PreAuthorize("hasPermission('/admin','c')")
    public String printAdminC() {
        return "如果你看见这句话，说明你有创建权限角色";
    }

    @RequestMapping("/user")
    @ResponseBody
//    @PreAuthorize("hasRole('ROLE_USER')")
    public String printUser() {
        return "如果你看见这句话，说明你有ROLE_USER角色";
    }

    @RequestMapping("/login/invalid")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ResponseBody
    public String invalid() {
        return "Session 已过期，请重新登录";
    }

    @Autowired
    private SessionRegistry sessionRegistry;

    /**
     * 认证成功的信息
     * @param authentication
     * @return
     */
    @GetMapping("/me")
    @ResponseBody
    public Object me(Authentication authentication) {
        return authentication;
    }

    /**
     * 用户信息
     * @param userDetails
     * @return
     */
    @GetMapping("/user/me")
    @ResponseBody
    public Object me(@AuthenticationPrincipal UserDetails userDetails) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info(authentication.toString());
        return userDetails;
    }

    /**
     * 发送验证码
     * @param mobile
     * @param session
     */
    @RequestMapping("/sms/code")
    @ResponseBody
    public void sms(String mobile, HttpSession session) {
        int code = (int) Math.ceil(Math.random() * 9000 + 1000);
        Map<String, Object> map = new HashMap<>(16);
        map.put("mobile", mobile);
        map.put("code", code);
        session.setAttribute("smsCode", map);
        log.info("{}：为 {} 设置短信验证码：{}", session.getId(), mobile, code);
    }

    /**
     * 踢出用户
     * @param username
     * @return
     */
    @GetMapping("/kick")
    @ResponseBody
    public String removeUserSessionByUsername(@RequestParam String username) {
        int count = 0;
        // 获取session中所有的用户信息
        List<Object> users = sessionRegistry.getAllPrincipals();
        for (Object principal : users) {
            if (principal instanceof User) {
                String principalName = ((User)principal).getUsername();
                if (principalName.equals(username)) {
                    // 参数二：是否包含过期的Session
                    List<SessionInformation> sessionsInfo = sessionRegistry.getAllSessions(principal, false);
                    if (null != sessionsInfo && sessionsInfo.size() > 0) {
                        for (SessionInformation sessionInformation : sessionsInfo) {
                            sessionInformation.expireNow();
                            count++;
                        }
                    }
                }
            }
        }
        return "操作成功，清理session共" + count + "个";
    }

}

