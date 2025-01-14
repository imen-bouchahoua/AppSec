INSERT INTO clients (
    allowed_roles,
    client_id,
    client_secret,
    redirect_uri,
    required_scopes,
    supported_grant_types
) VALUES (
             3,
             'appsec',
             'my-client-secret',
             'http://127.0.0.1:3000/index.html',
             'read write',
             'authorization_code'
         );

INSERT INTO users (username, password, roles, provided_scopes)
VALUES ('imen', '$argon2id$v=19$m=97579,t=23,p=2$cyJl09U3BbnLXounzHgMDQpOQcu6SMIo++wHWURO6xs$LwUyQropxUSCkeErWTacvjJnpOuEweJsAJ+OmLEWawG4f3yDiCvwMKeXl5fpfxGX1Zzo6xnGc0DRoBuUjxRV/d2sJLmleNRYWq2oy4geHlCXNKzUj54KrOcb+4w4bkk+UE9ft7Xrt1xh5eCgKxGeFiwH+TRpo8dbx03v1VlTAJM', 1, 'read');

INSERT INTO issued_grants (
    client_id,
    user_id,
    approved_scopes,
    issuance_date_time
) VALUES (
             1,
             1,
             'read',
             NOW()
         );

INSERT INTO users (username, password, roles, provided_scopes)
VALUES ('john', '$argon2id$v=19$m=97579,t=23,p=2$FnO+Dq2Be9jnCtrzB3QfJ/6JtnP1a2eKhgcVqSlZePI$FXt0ZcvbRiVlkJK+d9sQoODJC8ugcQK0PbIKQB+TBS1PZS6r7gHXij/LTwIOXSVYdaa+gZGbbzEw8pSTH3+T0lwuzpJ6La9OZFwd3mKbilmjSIIuC1g/XqhtLrFSClLy7p1XHgrOh1awBZCL2Ew/JyYAlHVn3vIKTYWKoS5IDIE', 1, 'read');
