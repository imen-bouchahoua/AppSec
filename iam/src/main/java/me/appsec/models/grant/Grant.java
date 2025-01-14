package me.appsec.models.grant;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import me.appsec.models.RootEntity;
import me.appsec.models.client.Client;
import me.appsec.models.user.User;

import java.time.LocalDateTime;

@Entity
@Table(name = "issued_grants")
@Getter
@Setter
public class Grant implements RootEntity<GrantPK> {
    @EmbeddedId
    private GrantPK id;

    @MapsId("clientId")
    @ManyToOne
    private Client client;

    @MapsId("userId")
    @ManyToOne
    private User user;

    @Column(name = "approved_scopes")
    private String approvedScopes;

    @Column(name = "issuance_date_time")
    private LocalDateTime issuanceDateTime;

    @Override
    public GrantPK getID() {
        return id;
    }

    @Override
    public void setID(GrantPK id) {
        this.id=id;
    }
}
