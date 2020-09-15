package com.spring.security.service;

import com.spring.security.dao.SysUserMapper;
import com.spring.security.pojo.SysUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(
            isolation = Isolation.REPEATABLE_READ, // 隔离级别
            readOnly = true,  //是否只读
            propagation = Propagation.REQUIRED, //传播特性
            timeout = 60,  // 超时时间
            rollbackFor = RuntimeException.class // 异常回滚
            )
public class SysUserService {

    @Autowired(required = false)
    private SysUserMapper userMapper;

    public SysUser selectById(Integer id) {
        return userMapper.selectById(id);
    }

    public SysUser selectByName(String name) {
        return userMapper.selectByName(name);
    }
}

