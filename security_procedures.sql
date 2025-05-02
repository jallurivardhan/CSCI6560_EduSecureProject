USE AcademyDB_Extended;

DELIMITER //

-- Procedure to list all roles
CREATE PROCEDURE sp_ListAllRoles()
BEGIN
    SELECT DISTINCT UserRole as RoleName, 
           CASE 
               WHEN UserRole = 'AdminRole' THEN 'Full administrative access'
               WHEN UserRole = 'FacultyRole' THEN 'Faculty and course management'
               WHEN UserRole = 'StudentRole' THEN 'Student access and self-service'
           END as Description
    FROM SystemUsers 
    ORDER BY UserRole;
END//

-- Procedure to list all users with their roles
CREATE PROCEDURE sp_ListAllUsers()
BEGIN
    SELECT 
        su.UserName,
        su.UserRole,
        su.LastLogin,
        su.AccountStatus,
        CASE 
            WHEN s.StudentID IS NOT NULL THEN 'Student'
            WHEN f.FacultyID IS NOT NULL THEN 'Faculty'
            WHEN a.AdminID IS NOT NULL THEN 'Admin'
        END AS UserType
    FROM SystemUsers su
    LEFT JOIN Students s ON su.UserName = s.StudentID
    LEFT JOIN Faculty f ON su.UserName = f.FacultyID
    LEFT JOIN Admin a ON su.UserName = a.AdminID
    ORDER BY su.UserRole, su.UserName;
END//

-- Procedure to show grants for a specific user
CREATE PROCEDURE sp_ShowUserGrants(IN p_Username VARCHAR(50))
BEGIN
    SELECT 
        su.UserName,
        su.UserRole,
        tp.TABLE_NAME,
        GROUP_CONCAT(tp.PRIVILEGE_TYPE) as Privileges
    FROM SystemUsers su
    LEFT JOIN information_schema.TABLE_PRIVILEGES tp ON tp.GRANTEE = su.UserRole
    WHERE su.UserName = p_Username
    AND tp.TABLE_SCHEMA = 'AcademyDB_Extended'
    GROUP BY su.UserName, su.UserRole, tp.TABLE_NAME;
END//

-- Procedure to show DCL audit logs
CREATE PROCEDURE sp_ShowDCLAuditLogs()
BEGIN
    SELECT 
        LogID,
        EventTime,
        UserID,
        EventType,
        EventDescription,
        IPAddress
    FROM SystemAuditLog
    WHERE EventType = 'DCL'
    ORDER BY EventTime DESC
    LIMIT 50;
END//

-- Function to check if a user has specific privilege
CREATE FUNCTION fn_HasPrivilege(
    p_Username VARCHAR(50),
    p_TableName VARCHAR(100),
    p_Privilege VARCHAR(50)
) 
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
    DECLARE v_has_privilege BOOLEAN;
    
    SELECT EXISTS (
        SELECT 1
        FROM information_schema.TABLE_PRIVILEGES tp
        JOIN SystemUsers su ON tp.GRANTEE = su.UserRole
        WHERE su.UserName = p_Username
        AND tp.TABLE_NAME = p_TableName
        AND tp.PRIVILEGE_TYPE = p_Privilege
        AND tp.TABLE_SCHEMA = 'AcademyDB_Extended'
    ) INTO v_has_privilege;
    
    RETURN v_has_privilege;
END//

-- Procedure to test user access
CREATE PROCEDURE sp_TestUserAccess(IN p_Username VARCHAR(50))
BEGIN
    DECLARE v_role VARCHAR(20);
    
    -- Get user's role
    SELECT UserRole INTO v_role
    FROM SystemUsers
    WHERE UserName = p_Username;
    
    -- Show user's basic info
    SELECT 
        UserName,
        UserRole,
        AccountStatus,
        LastLogin
    FROM SystemUsers
    WHERE UserName = p_Username;
    
    -- Show accessible views
    SELECT 
        TABLE_NAME,
        GROUP_CONCAT(PRIVILEGE_TYPE) as Privileges
    FROM information_schema.TABLE_PRIVILEGES
    WHERE GRANTEE = v_role
    AND TABLE_SCHEMA = 'AcademyDB_Extended'
    GROUP BY TABLE_NAME;
    
    -- Test specific permissions
    SELECT 
        'Students' as TableName,
        fn_HasPrivilege(p_Username, 'Students', 'SELECT') as CanSelect,
        fn_HasPrivilege(p_Username, 'Students', 'INSERT') as CanInsert,
        fn_HasPrivilege(p_Username, 'Students', 'UPDATE') as CanUpdate,
        fn_HasPrivilege(p_Username, 'Students', 'DELETE') as CanDelete
    UNION ALL
    SELECT 
        'Faculty',
        fn_HasPrivilege(p_Username, 'Faculty', 'SELECT'),
        fn_HasPrivilege(p_Username, 'Faculty', 'INSERT'),
        fn_HasPrivilege(p_Username, 'Faculty', 'UPDATE'),
        fn_HasPrivilege(p_Username, 'Faculty', 'DELETE')
    UNION ALL
    SELECT 
        'Results',
        fn_HasPrivilege(p_Username, 'Results', 'SELECT'),
        fn_HasPrivilege(p_Username, 'Results', 'INSERT'),
        fn_HasPrivilege(p_Username, 'Results', 'UPDATE'),
        fn_HasPrivilege(p_Username, 'Results', 'DELETE');
END//

-- Procedure to demonstrate all security features
CREATE PROCEDURE sp_DemonstrateSecurityFeatures()
BEGIN
    -- 1. Show roles and users
    CALL sp_ListAllRoles();
    CALL sp_ListAllUsers();
    
    -- 2. Show encryption status
    CALL sp_CheckColumnEncryptionKeyStatus();
    
    -- 3. Show masked vs unmasked data
    SELECT 'Original Data' as DataType, s.* 
    FROM Students s 
    LIMIT 2;
    
    SELECT 'Masked Data' as DataType, sm.* 
    FROM Students_Masked sm 
    LIMIT 2;
    
    -- 4. Show recent audit logs
    SELECT 'Recent Audit Events' as Report;
    SELECT 
        EventTime,
        EventType,
        UserID,
        EventDescription
    FROM SystemAuditLog
    ORDER BY EventTime DESC
    LIMIT 5;
    
    -- 5. Show role-based views
    SELECT 'Available Views' as Report;
    SELECT 
        TABLE_NAME,
        TABLE_TYPE,
        TABLE_COMMENT
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = 'AcademyDB_Extended'
    AND TABLE_TYPE = 'VIEW'
    AND TABLE_NAME LIKE '%View';
END//

-- First, check if we have an active encryption key and create one if needed
CREATE PROCEDURE IF NOT EXISTS sp_EnsureEncryptionKey()
BEGIN
    DECLARE v_key_exists INT;
    
    SELECT COUNT(*) INTO v_key_exists 
    FROM ColumnEncryptionKeys 
    WHERE KeyStatus = 'Active';
    
    IF v_key_exists = 0 THEN
        CALL sp_GenerateColumnEncryptionKey('DefaultKey', 365, 'Default encryption key');
    END IF;
END//

DELIMITER ;

CALL sp_EnsureEncryptionKey();

-- Insert some test users if they don't exist
INSERT IGNORE INTO Admin (AdminID, FullName, UserPassword, Contact, Email, AdditionalInfo)
SELECT 'Admin1', 'Admin User 1', 
       COALESCE(fn_encrypt('AdminPass123!'), 'AdminPass123!'),
       '1234567890', 'admin1@academy.edu', 'System Administrator'
WHERE NOT EXISTS (SELECT 1 FROM Admin WHERE AdminID = 'Admin1');

INSERT IGNORE INTO Admin (AdminID, FullName, UserPassword, Contact, Email, AdditionalInfo)
SELECT 'Admin2', 'Admin User 2', 
       COALESCE(fn_encrypt('AdminPass456!'), 'AdminPass456!'),
       '0987654321', 'admin2@academy.edu', 'System Administrator'
WHERE NOT EXISTS (SELECT 1 FROM Admin WHERE AdminID = 'Admin2');

INSERT IGNORE INTO Faculty (FacultyID, FullName, UserPassword, Contact, Email, Dept, AdditionalInfo)
SELECT 'Fac01', 'Faculty User 1', 
       COALESCE(fn_encrypt('FacultyPass123!'), 'FacultyPass123!'),
       '1112223333', 'fac01@academy.edu', 'Computer Science', 'Senior Lecturer'
WHERE NOT EXISTS (SELECT 1 FROM Faculty WHERE FacultyID = 'Fac01');

INSERT IGNORE INTO Faculty (FacultyID, FullName, UserPassword, Contact, Email, Dept, AdditionalInfo)
SELECT 'Fac02', 'Faculty User 2', 
       COALESCE(fn_encrypt('FacultyPass456!'), 'FacultyPass456!'),
       '4445556666', 'fac02@academy.edu', 'Mathematics', 'Assistant Professor'
WHERE NOT EXISTS (SELECT 1 FROM Faculty WHERE FacultyID = 'Fac02');

INSERT IGNORE INTO Students (StudentID, FullName, UserPassword, Contact, Email, AdditionalInfo)
SELECT 'Stu01', 'Student User 1', 
       COALESCE(fn_encrypt('StudentPass123!'), 'StudentPass123!'),
       '7778889999', 'stu01@academy.edu', 'First Year Student'
WHERE NOT EXISTS (SELECT 1 FROM Students WHERE StudentID = 'Stu01');

INSERT IGNORE INTO Students (StudentID, FullName, UserPassword, Contact, Email, AdditionalInfo)
SELECT 'Stu02', 'Student User 2', 
       COALESCE(fn_encrypt('StudentPass456!'), 'StudentPass456!'),
       '0001112222', 'stu02@academy.edu', 'Second Year Student'
WHERE NOT EXISTS (SELECT 1 FROM Students WHERE StudentID = 'Stu02');

DELIMITER ;

-- Grant execute permissions
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_ListAllRoles TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_ListAllUsers TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_ShowUserGrants TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_ShowDCLAuditLogs TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_TestUserAccess TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_DemonstrateSecurityFeatures TO AdminRole; 