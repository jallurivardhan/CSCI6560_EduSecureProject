-- Create combined view for Students and Faculty (login metadata from SystemUsers)
CREATE OR REPLACE VIEW UserDetailedView AS
SELECT 
    s.StudentID AS UserID,
    s.FullName,
    s.Email,
    s.Contact,
    'Student' AS UserType,
    su.LastLogin,
    su.FailedLoginCount
FROM Students s
JOIN SystemUsers su ON s.StudentID = su.UserName
UNION ALL
SELECT 
    f.FacultyID AS UserID,
    f.FullName,
    f.Email,
    f.Contact,
    'Faculty' AS UserType,
    su.LastLogin,
    su.FailedLoginCount
FROM Faculty f
JOIN SystemUsers su ON f.FacultyID = su.UserName;

DELIMITER ;

-- Create roles if not already created, excluding DataAdminRole
CREATE ROLE IF NOT EXISTS FacultyRole;
CREATE ROLE IF NOT EXISTS StudentRole;
CREATE ROLE IF NOT EXISTS AdminRole;

-- Create initial MySQL users and assign roles
CREATE USER IF NOT EXISTS 'Admin1'@'localhost' IDENTIFIED BY 'AdminPass123!';
CREATE USER IF NOT EXISTS 'Admin2'@'localhost' IDENTIFIED BY 'AdminPass456!';
CREATE USER IF NOT EXISTS 'Stu01'@'localhost' IDENTIFIED BY 'StudentPass123!';
CREATE USER IF NOT EXISTS 'Stu02'@'localhost' IDENTIFIED BY 'StudentPass456!';
CREATE USER IF NOT EXISTS 'Fac01'@'localhost' IDENTIFIED BY 'FacultyPass123!';
CREATE USER IF NOT EXISTS 'Fac02'@'localhost' IDENTIFIED BY 'FacultyPass456!';

-- Grant roles to users; Admin users receive AdminRole only
GRANT AdminRole TO 'Admin1'@'localhost', 'Admin2'@'localhost';
GRANT StudentRole TO 'Stu01'@'localhost', 'Stu02'@'localhost';
GRANT FacultyRole TO 'Fac01'@'localhost', 'Fac02'@'localhost';

SET DEFAULT ROLE ALL TO
    'Admin1'@'localhost',
    'Admin2'@'localhost',
    'Stu01'@'localhost',
    'Stu02'@'localhost',
    'Fac01'@'localhost',
    'Fac02'@'localhost';

-- Insert initial user credentials into SystemUsers table (from Section H)
INSERT IGNORE INTO SystemUsers (UserName, UserPassword)
VALUES
    ('Admin1', fn_encrypt('AdminPass123!')),
    ('Admin2', fn_encrypt('AdminPass456!')),
    ('Stu01',   fn_encrypt('StudentPass123!')),
    ('Stu02',   fn_encrypt('StudentPass456!')),
    ('Fac01',   fn_encrypt('FacultyPass123!')),
    ('Fac02',   fn_encrypt('FacultyPass456!'));

DELIMITER //

-- Procedure: Create a New User and assign a role
CREATE PROCEDURE sp_CreateNewUser(
    IN p_Username VARCHAR(50),
    IN p_Password VARCHAR(100),
    IN p_Role VARCHAR(50)
)
BEGIN
    -- Create the user if not exists
    SET @createUser = CONCAT('CREATE USER IF NOT EXISTS ''', p_Username, '''@''localhost'' IDENTIFIED BY ''', p_Password, '''');
    PREPARE stmt FROM @createUser;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Grant the specified role
    SET @grantRole = CONCAT('GRANT ', p_Role, ' TO ''', p_Username, '''@''localhost''');
    PREPARE stmt FROM @grantRole;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Set default role for the user
    SET @setDefault = CONCAT('SET DEFAULT ROLE ALL TO ''', p_Username, '''@''localhost''');
    PREPARE stmt FROM @setDefault;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    SELECT CONCAT('User ', p_Username, ' created and assigned role ', p_Role) AS Message;
END//

-- Procedure: Assign an additional role to an existing user
CREATE PROCEDURE sp_AssignRoleToUser(
    IN p_Username VARCHAR(50),
    IN p_Role VARCHAR(50)
)
BEGIN
    SET @sql = CONCAT('GRANT ', p_Role, ' TO ''', p_Username, '''@''localhost''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    SELECT CONCAT('Role ', p_Role, ' assigned to ', p_Username) AS Message;
END//

-- Procedure: Revoke a role from a user
CREATE PROCEDURE sp_RemoveUserFromRole(
    IN p_Username VARCHAR(50),
    IN p_Role VARCHAR(50)
)
BEGIN
    SET @sql = CONCAT('REVOKE ', p_Role, ' FROM ''', p_Username, '''@''localhost''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    SELECT CONCAT('Role ', p_Role, ' revoked from ', p_Username) AS Message;
END//

-- Procedure: Delete a user from MySQL
CREATE PROCEDURE sp_DeleteUser(
    IN p_Username VARCHAR(50)
)
BEGIN
    SET @sql = CONCAT('DROP USER IF EXISTS ''', p_Username, '''@''localhost''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    SELECT CONCAT('User ', p_Username, ' deleted.') AS Message;
END//

-- Procedure: Retrieve grants for a given user
CREATE PROCEDURE sp_ShowUserGrants(
    IN p_Username VARCHAR(50)
)
BEGIN
    SET @sql = CONCAT('SHOW GRANTS FOR ''', p_Username, '''@''localhost''');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END//

-- Procedure: List all users from the MySQL user table (for localhost)
CREATE PROCEDURE sp_ListAllUsers()
BEGIN
    SELECT User, Host FROM mysql.user WHERE Host = 'localhost';
END//

-- Procedure: List all defined roles
CREATE PROCEDURE sp_ListAllRoles()
BEGIN
    SELECT 'FacultyRole' AS Role
    UNION ALL
    SELECT 'StudentRole'
    UNION ALL
    SELECT 'AdminRole';
END//

DELIMITER ;
