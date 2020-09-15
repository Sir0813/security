package com.spring.security.pojo;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SysUser {

    static final long serialVersionUID = 1L;

    private Integer id;

    private String name;

    private String password;

}

