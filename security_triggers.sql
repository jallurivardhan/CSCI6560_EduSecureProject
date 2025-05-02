USE AcademyDB_Extended;

DELIMITER //

-- Trigger: Log all login attempts
CREATE TRIGGER IF NOT EXISTS trg_LogLoginAttempt
AFTER UPDATE ON SystemUsers
FOR EACH ROW
BEGIN
    IF NEW.LastLogin IS NOT NULL AND (OLD.LastLogin IS NULL OR NEW.LastLogin != OLD.LastLogin) THEN
        -- Successful login
        INSERT INTO SystemAuditLog (
            EventType,
            UserID,
            EventDescription,
            IPAddress,
            EventTime
        ) VALUES (
            'Login_Success',
            NEW.UserName,
            CONCAT('Successful login by ', NEW.UserName),
            SUBSTRING_INDEX(USER(), '@', -1),
            NOW()
        );
    END IF;
    
    IF NEW.FailedLoginCount > OLD.FailedLoginCount THEN
        -- Failed login attempt
        INSERT INTO SystemAuditLog (
            EventType,
            UserID,
            EventDescription,
            IPAddress,
            EventTime
        ) VALUES (
            'Login_Failure',
            NEW.UserName,
            CONCAT('Failed login attempt by ', NEW.UserName, ' (Attempt ', NEW.FailedLoginCount, ')'),
            SUBSTRING_INDEX(USER(), '@', -1),
            NOW()
        );
    END IF;
END//

-- Trigger: Log all data access attempts
CREATE TRIGGER IF NOT EXISTS trg_LogDataAccess
AFTER SELECT ON Students
FOR EACH ROW
BEGIN
    INSERT INTO SystemAuditLog (
        EventType,
        UserID,
        EventDescription,
        IPAddress,
        EventTime
    ) VALUES (
        'Data_Access',
        SUBSTRING_INDEX(USER(), '@', 1),
        CONCAT('Accessed student data for ID: ', OLD.StudentID),
        SUBSTRING_INDEX(USER(), '@', -1),
        NOW()
    );
END//

-- Trigger: Log all data modifications
CREATE TRIGGER IF NOT EXISTS trg_LogDataModification
AFTER UPDATE ON Students
FOR EACH ROW
BEGIN
    -- Log changes to sensitive data
    IF OLD.Contact != NEW.Contact OR OLD.Email != NEW.Email THEN
        INSERT INTO SystemAuditLog (
            EventType,
            UserID,
            EventDescription,
            IPAddress,
            EventTime
        ) VALUES (
            'Data_Modification',
            SUBSTRING_INDEX(USER(), '@', 1),
            CONCAT('Modified sensitive data for student: ', NEW.StudentID),
            SUBSTRING_INDEX(USER(), '@', -1),
            NOW()
        );
    END IF;
END//

-- Trigger: Enforce password policy
CREATE TRIGGER IF NOT EXISTS trg_EnforcePasswordPolicy
BEFORE UPDATE ON SystemUsers
FOR EACH ROW
BEGIN
    DECLARE password_length INT;
    DECLARE has_uppercase BOOLEAN;
    DECLARE has_lowercase BOOLEAN;
    DECLARE has_number BOOLEAN;
    DECLARE has_special BOOLEAN;
    
    IF NEW.UserPassword IS NOT NULL AND NEW.UserPassword != OLD.UserPassword THEN
        SET password_length = LENGTH(NEW.UserPassword);
        SET has_uppercase = NEW.UserPassword REGEXP '[A-Z]';
        SET has_lowercase = NEW.UserPassword REGEXP '[a-z]';
        SET has_number = NEW.UserPassword REGEXP '[0-9]';
        SET has_special = NEW.UserPassword REGEXP '[!@#$%^&*(),.?":{}|<>]';
        
        IF password_length < 8 OR 
           NOT has_uppercase OR 
           NOT has_lowercase OR 
           NOT has_number OR 
           NOT has_special THEN
            SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters';
        END IF;
    END IF;
END//

-- Trigger: Auto-lock account after multiple failed attempts
CREATE TRIGGER IF NOT EXISTS trg_AutoLockAccount
AFTER UPDATE ON SystemUsers
FOR EACH ROW
BEGIN
    IF NEW.FailedLoginCount >= 5 THEN
        -- Lock the account
        UPDATE SystemUsers
        SET UserPassword = NULL
        WHERE UserName = NEW.UserName;
        
        -- Log the account lock
        INSERT INTO SystemAuditLog (
            EventType,
            UserID,
            EventDescription,
            IPAddress,
            EventTime
        ) VALUES (
            'Account_Locked',
            NEW.UserName,
            'Account locked due to multiple failed login attempts',
            SUBSTRING_INDEX(USER(), '@', -1),
            NOW()
        );
    END IF;
END//

-- Trigger: Automatically encrypt sensitive data on insert
CREATE TRIGGER IF NOT EXISTS trg_EncryptStudentData_Insert
BEFORE INSERT ON Students
FOR EACH ROW
BEGIN
    -- Store plain text values for searching/indexing
    SET NEW.Contact_Plain = NEW.Contact;
    SET NEW.Email_Plain = NEW.Email;
    SET NEW.AdditionalInfo_Plain = NEW.AdditionalInfo;
    
    -- Encrypt sensitive data
    SET NEW.Contact = fn_encrypt(NEW.Contact);
    SET NEW.Email = fn_encrypt(NEW.Email);
    SET NEW.AdditionalInfo = fn_encrypt(NEW.AdditionalInfo);
END//

-- Trigger: Automatically encrypt sensitive data on update
CREATE TRIGGER IF NOT EXISTS trg_EncryptStudentData_Update
BEFORE UPDATE ON Students
FOR EACH ROW
BEGIN
    -- Only encrypt if the values have changed
    IF NEW.Contact != OLD.Contact THEN
        SET NEW.Contact_Plain = NEW.Contact;
        SET NEW.Contact = fn_encrypt(NEW.Contact);
    END IF;
    
    IF NEW.Email != OLD.Email THEN
        SET NEW.Email_Plain = NEW.Email;
        SET NEW.Email = fn_encrypt(NEW.Email);
    END IF;
    
    IF NEW.AdditionalInfo != OLD.AdditionalInfo THEN
        SET NEW.AdditionalInfo_Plain = NEW.AdditionalInfo;
        SET NEW.AdditionalInfo = fn_encrypt(NEW.AdditionalInfo);
    END IF;
END//

-- Trigger: Log access to decrypted data
CREATE TRIGGER IF NOT EXISTS trg_LogDecryptedAccess
AFTER SELECT ON Students_Decrypted
FOR EACH ROW
BEGIN
    INSERT INTO SystemAuditLog (
        EventType,
        UserID,
        EventDescription,
        IPAddress,
        EventTime
    ) VALUES (
        'Data_Access',
        SUBSTRING_INDEX(USER(), '@', 1),
        'Accessed decrypted student data',
        SUBSTRING_INDEX(USER(), '@', -1),
        NOW()
    );
END//

DELIMITER ; 