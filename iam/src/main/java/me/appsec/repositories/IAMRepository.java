package me.appsec.repositories;

import jakarta.ejb.Stateless;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.PersistenceContext;
import me.appsec.models.client.Client;
import me.appsec.models.grant.Grant;
import me.appsec.models.grant.GrantPK;
import me.appsec.models.user.Role;
import me.appsec.models.user.User;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

@Stateless
public class IAMRepository {
    @PersistenceContext
    private EntityManager entityManager;

    public Optional<Client> findClientByIdentifier(short identifier) {
        Client client = entityManager.find(Client.class, identifier);
        return Optional.ofNullable(client);
    }
    public Optional<Client> findClientByClientId(String clientId){
        try {
            Client client = entityManager.createQuery("select c from Client c where c.clientId =:name",Client.class)
                    .setParameter("name",clientId)
                    .getSingleResult();
            return Optional.of(client);
        }catch (NoResultException e){
            return Optional.empty();
        }
    }
    public List<Client> findAll() {
        return entityManager.createQuery("SELECT c FROM Client c", Client.class).getResultList();
    }
    public Optional<User> findUserByIdentifier(long identifier) {
        User user = entityManager.find(User.class, identifier);
        return Optional.ofNullable(user); // Enveloppe le résultat dans un Optional
    }
    public Optional<User> findUserByUsername(String username) {
        try {
            User user = entityManager.createQuery("select u from User u where u.username=:username", User.class)
                    .setParameter("username", username)
                    .getSingleResult();
            return Optional.ofNullable(user);
        } catch (NoResultException e) {
            return Optional.empty();
        }
    }
    public String[] getRoles(String username) {
        var query = entityManager.createQuery("select u.roles from User u where u.username=:username", Long.class);
        query.setParameter("username", username);
        var roles = query.getSingleResult();

        var ret = new HashSet<String>();
        for (Role role : Role.values()) {
            if ((roles & role.getValue()) != 0L) {
                String value = Role.byValue(role.getValue());
                if (value == null) {
                    continue;
                }
                ret.add(value);
            }
        }
        return ret.toArray(new String[0]);
    }
    public Optional<Grant> findGrant(String clientId, Long userId){
        if(findClientByClientId(clientId).isEmpty()){
            throw new IllegalArgumentException("Invalid Client Id!");
        }
        Client client = findClientByClientId(clientId).get();
        try {
            Grant grant = entityManager.createQuery(
                            "select g from Grant g where g.id.clientId = :clientId and g.id.userId = :userId",
                            Grant.class)
                    .setParameter("clientId", client.getID())
                    .setParameter("userId", userId)
                    .getSingleResult();
            return Optional.of(grant);
        } catch (NoResultException e) {
            return Optional.empty();
        }
    }
    public Optional<Grant> addGrant(String clientId, Long userId, String approvedScopes ){
        if(findClientByClientId(clientId).isEmpty()){
            throw new IllegalArgumentException("Invalid Client Id!");
        }
        Client client = findClientByClientId(clientId).get();

        if (findUserByIdentifier(userId).isEmpty()) {
            throw new IllegalArgumentException("Invalid User Id!");
        }
        User user =findUserByIdentifier(userId).get();

        Grant grant = new Grant();
        GrantPK grantPK = new GrantPK();
        grantPK.setClientId(client.getID());
        grantPK.setUserId(userId);


        grant.setID(grantPK);
        grant.setClient(client);
        grant.setUser(user);
        grant.setApprovedScopes(approvedScopes);
        grant.setIssuanceDateTime(LocalDateTime.now());

        try {
            entityManager.persist(grant);
            return Optional.of(grant);
        }catch (Exception e){
            return Optional.empty();
        }
    }
}