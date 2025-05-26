INSERT INTO tb_roles (role_id, name) VALUES (1, 'admin')
    ON DUPLICATE KEY UPDATE name = VALUES(name);
INSERT INTO tb_roles (role_id, name) VALUES (2, 'basic')
    ON DUPLICATE KEY UPDATE name = VALUES(name);
