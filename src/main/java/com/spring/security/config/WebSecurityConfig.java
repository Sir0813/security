package com.spring.security.config;

import com.spring.security.filter.VerifyFilter;
import com.spring.security.handler.CustomAuthenticationFailureHandler;
import com.spring.security.handler.CustomAuthenticationSuccessHandler;
import com.spring.security.handler.CustomLogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import javax.sql.DataSource;
/**
 * @EnableWebSecurity
 * 1: 加载了WebSecurityConfiguration配置类, 配置安全认证策略。
 * 2: 加载了AuthenticationConfiguration, 配置了认证信息。
 */
/**
 * @EnableGlobalMethodSecurity(securedEnabled=true) 开启@Secured 注解过滤权限
 * @EnableGlobalMethodSecurity(jsr250Enabled=true)开启@RolesAllowed 注解过滤权限 
 * @EnableGlobalMethodSecurity(prePostEnabled=true) 使用表达式时间方法级别的安全性  4个注解可用
 * @PreAuthorize 在方法调用之前, 基于表达式的计算结果来限制对方法的访问
 * @PostAuthorize 允许方法调用, 但是如果表达式计算结果为false, 将抛出一个安全性异常
 * @PostFilter 允许方法调用, 但必须按照表达式来过滤方法的结果
 * @PreFilter 允许方法调用, 但必须在进入方法之前过滤输入值
 */
/**
 * spring security 主配置类
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 登录
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 记住我 功能用到
     */
    @Autowired
    private DataSource dataSource;

    /**
     * 登录成功业务处理
     */
    @Autowired
    private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    /**
     * 登录失败业务处理
     */
    @Autowired
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    /**
     * 退出成功业务处理
     */
    @Autowired
    private CustomLogoutSuccessHandler logoutSuccessHandler;

    /**
     * 验证码登录配置类
     */
    @Autowired
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

    /**
     * 记住我 功能用到
     * 底层代码会有生成表 插入数据 修改数据 等等可以看 JdbcTokenRepositoryImpl
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
//         如果token表不存在，使用下面语句可以初始化该表；若存在，请注释掉这条语句，否则会报错。
//         tokenRepository.setCreateTableOnStartup(true);
    }

    /**
     * 在WebSecurityConfig类中的注册bean webSecurityExpressionHandler时会报无法创建，不能覆盖，
     * 解决办法：在application.yml中加上spring.main.allow-bean-definition-overriding: true #当遇到同样名字的时候，是否允许覆盖注册。
     * 我是改了名字  改为  newWebSecurityExpressionHandler
     * @return
     */
    @Bean
    public DefaultWebSecurityExpressionHandler newWebSecurityExpressionHandler(){
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setPermissionEvaluator(new CustomPermissionEvaluator());
        return handler;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//         未注册用户
        provider.setHideUserNotFoundExceptions(false);
        provider.setUserDetailsService(userDetailsService);
//         密码加密
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        return provider;
    }

    /**
     *  角色继承 SpringBoot2.0中这样写
     *  admin权限大于user  也就是user能访问的接口admin都能访问
     * @return
     */
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = "ROLE_ADMIN > ROLE_USER";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }

    /**
     * SpringBoot2.1中这样写
     */
    /*@Bean
    public RoleHierarchy roleHierarchy() {
        String separator = System.lineSeparator();
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = "ROLE_ADMIN > ROLE_USER " + separator + " ROLE_USER > ROLE_TOURISTS";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }*/

    /**
     * 主动踢出用户
     * @return
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * 初始配置
     * @param auth
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider());
    }

    /**
     * 登录 重写configure方法覆盖之前的方法
     * 加入自己的
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.apply(smsCodeAuthenticationSecurityConfig).and().authorizeRequests()
//                 如果有允许匿名的url，填在下面
                .antMatchers("/login/invalid","/getVerifyCode","/sms/**","/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login")
//                .loginProcessingUrl("登录url")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
//                 设置登陆成功页
                .permitAll()
//                 自定义登陆用户名和密码参数，默认为username和password
//                .usernameParameter("username")
//                .passwordParameter("password")
                .and()
                .addFilterBefore(new VerifyFilter(), UsernamePasswordAuthenticationFilter.class)
                .logout()
//                 退出登录url
                .logoutUrl("/logout")
                .deleteCookies("JSESSIONID")
//                 退出登录逻辑处理
                .logoutSuccessHandler(logoutSuccessHandler)
//                 记住我
                .and().rememberMe().tokenRepository(persistentTokenRepository())
                .tokenValiditySeconds(60).userDetailsService(userDetailsService)
//                 session 请求超时配置
                .and().sessionManagement()
//                 session超时请求的地址
                .invalidSessionUrl("/login/invalid")
//                 最大登录数
                .maximumSessions(1)
//                 当达到最大值时，是否保留已经登录的用户 true 新用户等不不上 false 新用户登录 已登录用户被踢掉
                .maxSessionsPreventsLogin(false)
//                 当达到最大值时，旧用户被踢出后的操作
                .expiredSessionStrategy(new CustomExpiredSessionStrategy())
                .sessionRegistry(sessionRegistry());
//         关闭CSRF跨域
        http.csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
//         设置拦截忽略文件夹，可以对静态资源放行
        web.ignoring().antMatchers("/css/**", "/js/**");
    }
}

