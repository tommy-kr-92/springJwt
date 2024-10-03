package com.tommy.springJwt.model;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Enumerated(value = EnumType.STRING)
    private Role role;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getUsername() {
        return username;
    }

    /*
     * 계정의 만료 여부
     * true를 반환하면 계정이 만료되지 않았음을 의미, User는 정상적으로 인증 절차를 진행
     * 여기서는 항상 true를 사용하여 계정 만료 기능을 사용하지 않음
     * 계정 만료 기능 구현 -> accountExpired와 같은 필드를 추가하고
     * 해당 필드의 값을 기반으로 반환값을 결정
     * */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /*
    * 계정의 잠금 여부
    * true 반환 -> 계정이 잠겨 있지 않음
    * 로그인 실패 횟수에 따라 계정을 잠그는 기능 구현 -> accountLocked와 같은 필드를 추가하고
    * 해당 필드의 값을 기반으로 반환값 경정
    * */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /*
    * 자격 증명의 만료 여부
    * 자격 증명이란 비밀번호와 같은 인증 수단을 의미
    * true를 반환하면 자격 증명이 만료되지 않았음을 의미
    * 비밀번호 유효 기간을 설정하여 일정 기간 후 비밀번호를 변경하도록 강제하려면
    * 관련 필드를 추가하고 로직을 구현
    * */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /*
    * 계정의 활성화 여부
    * true를 반환하면 계정이 활성화되어 있음을 의미, 사용자는 인증을 시도할 수 있음
    * 계정 비활성화 기능 구현 -> enabled와 같은 필드를 추가하여
    * 사용자에게 이메일 인증이나 관리자 승인이 필요할 때 활용
    * */
    @Override
    public boolean isEnabled() {
        return true;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    // implement UsersDetail

    /*
    * Role 및 Authorities(권한) 반환
    * 사용자에게 부여된 권한이나 역할의 컬렉션 반환
    * GrantedAuthority 인터페이스를 구현한 객체들의 켈렉션 반환
    * User의 role을 기반프로 SimleGrantedAuthority 객체를 생성하고
    * 리스트로 감싸서 반환
    * */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    /*
    * 사용자의 비밀번호를 반환
    * 인증 과정에서 입력된 비밀번호 데이터베이스에 저장된 비밀번호를 비교하기 위해 사용
    * 비밀번호는 일반적으로 해시화되어 저장, 인증 프로세스에서는 해시된 비밀번호 사용
    * */
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}
