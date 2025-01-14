package me.appsec.models.grant;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.io.Serializable;

@Embeddable
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
public class GrantPK implements Serializable {
    @Column(name = "client_id",nullable = false)
    private Short clientId;
    @Column(name = "user_id",nullable = false)
    private Long userId;
}
