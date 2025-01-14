package me.appsec.models.user;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import me.appsec.models.RootEntity;

import java.security.Principal;

@Entity
@Getter
@Setter
@Table(name = "users")
public class User implements RootEntity<Long>,Principal {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 191,unique = true,nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private Long roles;

    @Column(name = "provided_scopes",nullable = false)
    private String providedScopes;


    @Override
    public String getName() {
        return username;
    }

    @Override
    public Long getID() {
        return id;
    }

    @Override
    public void setID(Long id) {
        this.id=id;
    }
}
