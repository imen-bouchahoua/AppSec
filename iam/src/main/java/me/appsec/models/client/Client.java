package me.appsec.models.client;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;
import me.appsec.models.RootEntity;
import org.hibernate.envers.Audited;


@Entity
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name="clients")
@Audited
public class Client implements RootEntity<Short> {

    /** Technical Identifier. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Short id;

    /** Unique identifier for client. */
    @Column(name = "client_id",nullable = false,unique = true,length = 191)
    private String clientId;

    @Column(name="client_secret", nullable = false)
    private String secret;

    @Column(name = "redirect_uri",nullable = false)
    private String redirectUris;

    @Column(name = "allowed_roles",nullable = false)
    private Long allowedRoles;

    @Column(name = "required_scopes",nullable = false)
    private String requiredScopes;

    @Column(name = "supported_grant_types",nullable = false)
    private String supportedGrantTypes;

    @Override
    public Short getID() {
        return id;
    }

    @Override
    public void setID(Short id) {
        this.id=id;
    }

}
