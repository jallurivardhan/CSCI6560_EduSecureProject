-- Column-Level Encryption (CLE) Implementation for AcademyDB_Extended
-- This file implements column-level encryption for sensitive data

USE AcademyDB_Extended;

-- ======================================================
-- Column-Level Encryption Implementation
-- ======================================================

-- Create a table to store encryption keys if not exists
CREATE TABLE IF NOT EXISTS ColumnEncryptionKeys (
    KeyID INT AUTO_INCREMENT PRIMARY KEY,
    KeyName VARCHAR(100) NOT NULL UNIQUE,
    EncryptionKey VARBINARY(8000) NOT NULL,
    CreationDate DATETIME DEFAULT CURRENT_TIMESTAMP,
    ExpiryDate DATETIME,
    KeyStatus ENUM('Active', 'Inactive', 'Compromised') DEFAULT 'Active',
    LastRotated DATETIME DEFAULT CURRENT_TIMESTAMP,
    Comments VARCHAR(255)
);

-- Create functions for encryption and decryption
DELIMITER //

-- Function to encrypt data using AES-256
CREATE FUNCTION fn_encrypt(data VARCHAR(1000)) 
RETURNS VARBINARY(1000) DETERMINISTIC
BEGIN
    DECLARE encryption_key VARBINARY(8000);
    
    -- Get the active encryption key
    SELECT EncryptionKey INTO encryption_key
    FROM ColumnEncryptionKeys
    WHERE KeyStatus = 'Active'
    ORDER BY CreationDate DESC
    LIMIT 1;
    
    -- If no key is found, use a default for demo purposes (not secure for production)
    IF encryption_key IS NULL THEN
        SET encryption_key = UNHEX(SHA2('DefaultEncryptionKey', 256));
    END IF;
    
    -- Encrypt data using AES-256 in CBC mode
    RETURN AES_ENCRYPT(data, encryption_key);
END//

-- Function to decrypt data using AES-256
CREATE FUNCTION fn_decrypt(encrypted_data VARBINARY(1000)) 
RETURNS VARCHAR(1000) DETERMINISTIC
BEGIN
    DECLARE encryption_key VARBINARY(8000);
    
    -- Get the active encryption key
    SELECT EncryptionKey INTO encryption_key
    FROM ColumnEncryptionKeys
    WHERE KeyStatus = 'Active'
    ORDER BY CreationDate DESC
    LIMIT 1;
    
    -- If no key is found, use a default for demo purposes (not secure for production)
    IF encryption_key IS NULL THEN
        SET encryption_key = UNHEX(SHA2('DefaultEncryptionKey', 256));
    END IF;
    
    -- Decrypt data
    RETURN AES_DECRYPT(encrypted_data, encryption_key);
END//

-- Function to generate a new encryption key
CREATE PROCEDURE sp_GenerateColumnEncryptionKey(
    IN p_KeyName VARCHAR(100),
    IN p_ExpiryDays INT,
    IN p_Comments VARCHAR(255)
)
BEGIN
    DECLARE v_EncryptionKey VARBINARY(8000);
    DECLARE v_ExpiryDate DATETIME;
    
    -- Generate a random key using SHA2 and UUID
    SET v_EncryptionKey = UNHEX(SHA2(CONCAT(UUID(), RAND()), 256));
    
    -- Calculate expiry date
    SET v_ExpiryDate = DATE_ADD(NOW(), INTERVAL p_ExpiryDays DAY);
    
    -- Insert the new key
    INSERT INTO ColumnEncryptionKeys (
        KeyName, 
        EncryptionKey, 
        ExpiryDate, 
        Comments
    )
    VALUES (
        p_KeyName,
        v_EncryptionKey,
        v_ExpiryDate,
        p_Comments
    );
    
    SELECT CONCAT('Encryption key "', p_KeyName, '" generated successfully.') AS Message;
END//

-- Procedure to rotate encryption keys
CREATE PROCEDURE sp_RotateColumnEncryptionKey(
    IN p_OldKeyName VARCHAR(100),
    IN p_NewKeyName VARCHAR(100),
    IN p_ExpiryDays INT,
    IN p_Comments VARCHAR(255)
)
BEGIN
    DECLARE v_OldKeyExists INT;
    DECLARE v_OldKey VARBINARY(8000);
    DECLARE v_NewKey VARBINARY(8000);
    
    -- Check if old key exists and is active
    SELECT COUNT(*), EncryptionKey INTO v_OldKeyExists, v_OldKey
    FROM ColumnEncryptionKeys
    WHERE KeyName = p_OldKeyName AND KeyStatus = 'Active'
    GROUP BY EncryptionKey;
    
    IF v_OldKeyExists = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Error: The specified old key does not exist or is inactive.';
    END IF;
    
    -- Start transaction for atomicity
    START TRANSACTION;
    
    -- Generate new encryption key
    CALL sp_GenerateColumnEncryptionKey(p_NewKeyName, p_ExpiryDays, p_Comments);
    
    -- Get the new key
    SELECT EncryptionKey INTO v_NewKey
    FROM ColumnEncryptionKeys
    WHERE KeyName = p_NewKeyName;
    
    -- Re-encrypt all sensitive columns in Students table
    UPDATE Students
    SET UserPassword = AES_ENCRYPT(AES_DECRYPT(UserPassword, v_OldKey), v_NewKey);
    
    -- Re-encrypt all sensitive columns in Faculty table
    UPDATE Faculty
    SET UserPassword = AES_ENCRYPT(AES_DECRYPT(UserPassword, v_OldKey), v_NewKey);
    
    -- Re-encrypt all sensitive columns in Admin table
    UPDATE Admin
    SET UserPassword = AES_ENCRYPT(AES_DECRYPT(UserPassword, v_OldKey), v_NewKey);
    
    -- Re-encrypt all sensitive columns in SystemUsers table
    UPDATE SystemUsers
    SET UserPassword = AES_ENCRYPT(AES_DECRYPT(UserPassword, v_OldKey), v_NewKey);
    
    -- Mark old key as inactive
    UPDATE ColumnEncryptionKeys 
    SET KeyStatus = 'Inactive',
        LastRotated = NOW()
    WHERE KeyName = p_OldKeyName;
    
    COMMIT;
    
    SELECT CONCAT('Key rotation completed successfully. Old key "', p_OldKeyName, '" is now inactive.') AS Message;
END//

-- Procedure to check column encryption key status
CREATE PROCEDURE sp_CheckColumnEncryptionKeyStatus()
BEGIN
    SELECT 
        KeyName,
        KeyStatus,
        CreationDate,
        ExpiryDate,
        DATEDIFF(ExpiryDate, NOW()) AS DaysToExpiry,
        CASE 
            WHEN DATEDIFF(ExpiryDate, NOW()) <= 0 THEN 'EXPIRED'
            WHEN DATEDIFF(ExpiryDate, NOW()) <= 7 THEN 'EXPIRING SOON'
            WHEN DATEDIFF(ExpiryDate, NOW()) <= 30 THEN 'NOTICE'
            ELSE 'OK'
        END AS Status,
        LastRotated,
        Comments
    FROM ColumnEncryptionKeys
    ORDER BY KeyStatus, ExpiryDate;
END//

-- Procedure to add encrypted columns to existing tables
CREATE PROCEDURE sp_AddEncryptedColumn(
    IN p_TableName VARCHAR(100),
    IN p_ColumnName VARCHAR(100),
    IN p_DataType VARCHAR(100)
)
BEGIN
    -- Construct the ALTER TABLE statement
    SET @sql = CONCAT(
        'ALTER TABLE ', p_TableName,
        ' ADD COLUMN ', p_ColumnName, '_Encrypted ', p_DataType, ' AFTER ', p_ColumnName
    );
    
    -- Execute the statement
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Log the addition of encrypted column
    INSERT INTO SystemAuditLog (EventType, EventDescription, AffectedObject, Username)
    VALUES ('SECURITY', CONCAT('Added encrypted column ', p_ColumnName, '_Encrypted'), 
            p_TableName, SUBSTRING_INDEX(USER(), '@', 1));
    
    SELECT CONCAT('Added encrypted column ', p_ColumnName, '_Encrypted to table ', p_TableName, '.') AS Message;
END//

-- Procedure to encrypt existing data
CREATE PROCEDURE sp_EncryptExistingData(
    IN p_TableName VARCHAR(100),
    IN p_ColumnName VARCHAR(100)
)
BEGIN
    -- Verify the encrypted column exists
    SET @sql = CONCAT('
        SELECT COUNT(*) INTO @column_exists
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
        AND table_name = "', p_TableName, '"
        AND column_name = "', p_ColumnName, '_Encrypted"
    ');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    IF @column_exists = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Error: The specified encrypted column does not exist.';
    END IF;
    
    -- Update the encrypted column with encrypted values
    SET @sql = CONCAT('
        UPDATE ', p_TableName, '
        SET ', p_ColumnName, '_Encrypted = fn_encrypt(', p_ColumnName, ')
    ');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Log the encryption operation
    INSERT INTO SystemAuditLog (EventType, EventDescription, AffectedObject, Username)
    VALUES ('SECURITY', CONCAT('Encrypted data in column ', p_ColumnName), 
            p_TableName, SUBSTRING_INDEX(USER(), '@', 1));
    
    SELECT CONCAT('Successfully encrypted data from column ', p_ColumnName, ' in table ', p_TableName, '.') AS Message;
END//

-- Procedure to drop the original column after encryption
CREATE PROCEDURE sp_RemoveOriginalColumn(
    IN p_TableName VARCHAR(100),
    IN p_ColumnName VARCHAR(100),
    IN p_DataType VARCHAR(100)
)
BEGIN
    -- Verify both columns exist
    SET @sql = CONCAT('
        SELECT 
            SUM(CASE WHEN column_name = "', p_ColumnName, '" THEN 1 ELSE 0 END) INTO @original_exists,
            SUM(CASE WHEN column_name = "', p_ColumnName, '_Encrypted" THEN 1 ELSE 0 END) INTO @encrypted_exists
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
        AND table_name = "', p_TableName, '"
    ');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    IF @original_exists = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Error: The specified original column does not exist.';
    END IF;
    
    IF @encrypted_exists = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Error: The encrypted column does not exist. Encrypt data first.';
    END IF;
    
    -- Drop the original column
    SET @sql = CONCAT('
        ALTER TABLE ', p_TableName, '
        DROP COLUMN ', p_ColumnName
    );
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Rename the encrypted column to the original name
    SET @sql = CONCAT('
        ALTER TABLE ', p_TableName, '
        CHANGE COLUMN ', p_ColumnName, '_Encrypted ', p_ColumnName, ' ', p_DataType
    );
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Log the column removal
    INSERT INTO SystemAuditLog (EventType, EventDescription, AffectedObject, Username)
    VALUES ('SECURITY', CONCAT('Removed original column and renamed encrypted column to ', p_ColumnName), 
            p_TableName, SUBSTRING_INDEX(USER(), '@', 1));
    
    SELECT CONCAT('Original column removed and encrypted column renamed to ', p_ColumnName, '.') AS Message;
END//

-- Create decryption view to easily access encrypted data
CREATE PROCEDURE sp_CreateDecryptionView(
    IN p_TableName VARCHAR(100)
)
BEGIN
    DECLARE v_ColumnList TEXT;
    DECLARE v_EncryptedColumns TEXT;
    DECLARE v_ViewName VARCHAR(100);
    
    -- Get a list of column names
    SET @sql = CONCAT('
        SELECT 
            GROUP_CONCAT(
                CASE 
                    WHEN DATA_TYPE = "varbinary" THEN CONCAT("fn_decrypt(", COLUMN_NAME, ") AS ", COLUMN_NAME)
                    ELSE COLUMN_NAME
                END
                SEPARATOR ", "
            ) INTO @column_list
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
        AND table_name = "', p_TableName, '"
    ');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Set the view name
    SET v_ViewName = CONCAT(p_TableName, '_Decrypted');
    
    -- Create or replace the view
    SET @sql = CONCAT('
        CREATE OR REPLACE VIEW ', v_ViewName, ' AS
        SELECT ', @column_list, '
        FROM ', p_TableName
    );
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Grant permissions on the view
    SET @sql = CONCAT('GRANT SELECT ON ', v_ViewName, ' TO AdminRole');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Log the view creation
    INSERT INTO SystemAuditLog (EventType, EventDescription, AffectedObject, Username)
    VALUES ('SECURITY', CONCAT('Created decryption view ', v_ViewName), 
            p_TableName, SUBSTRING_INDEX(USER(), '@', 1));
    
    SELECT CONCAT('Decryption view ', v_ViewName, ' created successfully.') AS Message;
END//

-- Procedure to migrate a table to use column-level encryption
CREATE PROCEDURE sp_MigrateToColumnEncryption(
    IN p_TableName VARCHAR(100),
    IN p_SensitiveColumns TEXT, -- Comma-separated list of columns to encrypt
    IN p_KeyName VARCHAR(100)
)
BEGIN
    DECLARE v_Column VARCHAR(100);
    DECLARE v_DataType VARCHAR(100);
    DECLARE v_Done INT DEFAULT FALSE;
    DECLARE v_ActiveKeyExists INT;
    
    -- Check if an active encryption key exists
    SELECT COUNT(*) INTO v_ActiveKeyExists
    FROM ColumnEncryptionKeys
    WHERE KeyStatus = 'Active';
    
    IF v_ActiveKeyExists = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Error: No active encryption key found. Generate a key first.';
    END IF;
    
    -- Create a cursor for the sensitive columns
    DECLARE cur CURSOR FOR
    SELECT 
        column_name, 
        CASE 
            WHEN DATA_TYPE = 'varchar' THEN CONCAT('VARBINARY(', CHARACTER_MAXIMUM_LENGTH, ')')
            WHEN DATA_TYPE = 'char' THEN CONCAT('VARBINARY(', CHARACTER_MAXIMUM_LENGTH, ')')
            WHEN DATA_TYPE = 'text' THEN 'VARBINARY(2000)'
            ELSE 'VARBINARY(1000)'
        END AS data_type
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
    AND table_name = p_TableName
    AND FIND_IN_SET(column_name, p_SensitiveColumns) > 0;
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_Done = TRUE;
    
    -- Start transaction
    START TRANSACTION;
    
    OPEN cur;
    
    column_loop: LOOP
        FETCH cur INTO v_Column, v_DataType;
        IF v_Done THEN
            LEAVE column_loop;
        END IF;
        
        -- Add encrypted column
        CALL sp_AddEncryptedColumn(p_TableName, v_Column, v_DataType);
        
        -- Encrypt existing data
        CALL sp_EncryptExistingData(p_TableName, v_Column);
        
        -- Remove original column and rename encrypted column
        CALL sp_RemoveOriginalColumn(p_TableName, v_Column, v_DataType);
    END LOOP;
    
    CLOSE cur;
    
    -- Create decryption view
    CALL sp_CreateDecryptionView(p_TableName);
    
    COMMIT;
    
    SELECT CONCAT('Successfully migrated table ', p_TableName, ' to use column-level encryption.') AS Message;
END//

-- Procedure to grant decrypt privileges to roles
CREATE PROCEDURE sp_GrantDecryptPrivilege(
    IN p_Role VARCHAR(50),
    IN p_TableName VARCHAR(100),
    IN p_ColumnName VARCHAR(100)
)
BEGIN
    -- Create a specific decryption function for this column
    SET @func_name = CONCAT('fn_decrypt_', p_TableName, '_', p_ColumnName);
    
    SET @sql = CONCAT('
        CREATE FUNCTION ', @func_name, '(encrypted_data VARBINARY(1000)) 
        RETURNS VARCHAR(1000) DETERMINISTIC
        BEGIN
            RETURN fn_decrypt(encrypted_data);
        END
    ');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Grant EXECUTE privilege on the function to the role
    SET @sql = CONCAT('GRANT EXECUTE ON FUNCTION ', @func_name, ' TO ', p_Role);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Log the grant
    INSERT INTO SystemAuditLog (EventType, EventDescription, AffectedObject, Username)
    VALUES ('SECURITY', CONCAT('Granted decrypt privilege on ', p_TableName, '.', p_ColumnName, ' to role ', p_Role), 
            CONCAT(@func_name, ' (FUNCTION)'), SUBSTRING_INDEX(USER(), '@', 1));
    
    SELECT CONCAT('Decrypt privilege granted to role ', p_Role, ' for ', p_TableName, '.', p_ColumnName, '.') AS Message;
END//

-- Procedure to revoke decrypt privileges
CREATE PROCEDURE sp_RevokeDecryptPrivilege(
    IN p_Role VARCHAR(50),
    IN p_TableName VARCHAR(100),
    IN p_ColumnName VARCHAR(100)
)
BEGIN
    -- Get the specific decryption function for this column
    SET @func_name = CONCAT('fn_decrypt_', p_TableName, '_', p_ColumnName);
    
    -- Revoke EXECUTE privilege on the function from the role
    SET @sql = CONCAT('REVOKE EXECUTE ON FUNCTION ', @func_name, ' FROM ', p_Role);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    -- Log the revocation
    INSERT INTO SystemAuditLog (EventType, EventDescription, AffectedObject, Username)
    VALUES ('SECURITY', CONCAT('Revoked decrypt privilege on ', p_TableName, '.', p_ColumnName, ' from role ', p_Role), 
            CONCAT(@func_name, ' (FUNCTION)'), SUBSTRING_INDEX(USER(), '@', 1));
    
    SELECT CONCAT('Decrypt privilege revoked from role ', p_Role, ' for ', p_TableName, '.', p_ColumnName, '.') AS Message;
END//

-- Procedure to analyze encryption impact
CREATE PROCEDURE sp_AnalyzeEncryptionImpact(
    IN p_TableName VARCHAR(100)
)
BEGIN
    -- Check table size before and theoretical size after encryption
    SELECT 
        t.TABLE_NAME,
        t.TABLE_ROWS,
        ROUND((t.DATA_LENGTH + t.INDEX_LENGTH) / 1024 / 1024, 2) AS SizeMB,
        COUNT(CASE WHEN c.DATA_TYPE IN ('varchar', 'char', 'text') THEN 1 END) AS EncryptableColumns,
        ROUND(((t.DATA_LENGTH + t.INDEX_LENGTH) * 1.3) / 1024 / 1024, 2) AS EstimatedSizeAfterEncryptionMB,
        ROUND(((t.DATA_LENGTH + t.INDEX_LENGTH) * 1.3 - (t.DATA_LENGTH + t.INDEX_LENGTH)) / 1024 / 1024, 2) AS SizeIncreaseMB,
        ROUND((((t.DATA_LENGTH + t.INDEX_LENGTH) * 1.3) / (t.DATA_LENGTH + t.INDEX_LENGTH) - 1) * 100, 2) AS SizeIncreasePercent
    FROM 
        information_schema.TABLES t
    JOIN
        information_schema.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA
    WHERE 
        t.TABLE_SCHEMA = DATABASE()
        AND t.TABLE_NAME = p_TableName
    GROUP BY
        t.TABLE_NAME,
        t.TABLE_ROWS,
        t.DATA_LENGTH,
        t.INDEX_LENGTH;
    
    -- Show columns that would be candidates for encryption
    SELECT 
        COLUMN_NAME,
        DATA_TYPE,
        CHARACTER_MAXIMUM_LENGTH,
        IS_NULLABLE,
        COLUMN_KEY,
        CASE 
            WHEN COLUMN_NAME LIKE '%password%' THEN 'High'
            WHEN COLUMN_NAME IN ('email', 'contact', 'phone', 'address', 'ssn', 'credit_card') THEN 'High'
            WHEN DATA_TYPE IN ('varchar', 'char', 'text') THEN 'Medium'
            ELSE 'Low'
        END AS EncryptionPriority
    FROM 
        information_schema.COLUMNS
    WHERE 
        TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = p_TableName
    ORDER BY 
        CASE 
            WHEN COLUMN_NAME LIKE '%password%' THEN 1
            WHEN COLUMN_NAME IN ('email', 'contact', 'phone', 'address', 'ssn', 'credit_card') THEN 2
            WHEN DATA_TYPE IN ('varchar', 'char', 'text') THEN 3
            ELSE 4
        END;
END//

DELIMITER ;

-- Grant appropriate permissions
GRANT EXECUTE ON FUNCTION AcademyDB_Extended.fn_encrypt TO AdminRole;
GRANT EXECUTE ON FUNCTION AcademyDB_Extended.fn_decrypt TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_GenerateColumnEncryptionKey TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_RotateColumnEncryptionKey TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_CheckColumnEncryptionKeyStatus TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_AddEncryptedColumn TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_EncryptExistingData TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_RemoveOriginalColumn TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_CreateDecryptionView TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_MigrateToColumnEncryption TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_GrantDecryptPrivilege TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_RevokeDecryptPrivilege TO AdminRole;
GRANT EXECUTE ON PROCEDURE AcademyDB_Extended.sp_AnalyzeEncryptionImpact TO AdminRole;

-- Documentation of CLE Processes

/*
COLUMN-LEVEL ENCRYPTION (CLE) IMPLEMENTATION GUIDE

This implementation provides column-level encryption for sensitive data in the 
AcademyDB_Extended database. Unlike TDE which encrypts the whole database files,
CLE allows for selective encryption of specific sensitive columns.

Usage Instructions:

1. Generate a Column Encryption Key:
   CALL sp_GenerateColumnEncryptionKey('MyCLEKey', 365, 'For encrypting sensitive user data');
   
2. Check Key Status:
   CALL sp_CheckColumnEncryptionKeyStatus();
   
3. Analyze Impact Before Encryption:
   CALL sp_AnalyzeEncryptionImpact('Students');
   
4. Migrate a Table to Use Column Encryption:
   CALL sp_MigrateToColumnEncryption('Students', 'Email,Contact,AdditionalInfo', 'MyCLEKey');
   
5. Access Decrypted Data (Admin only by default):
   SELECT * FROM Students_Decrypted;
   
6. Grant Decrypt Privileges to Other Roles (if needed):
   CALL sp_GrantDecryptPrivilege('FacultyRole', 'Students', 'Contact');
   
7. Revoke Decrypt Privileges:
   CALL sp_RevokeDecryptPrivilege('FacultyRole', 'Students', 'Contact');
   
8. Rotate Encryption Keys (recommended every 90-180 days):
   CALL sp_RotateColumnEncryptionKey('MyCLEKey', 'NewCLEKey', 365, 'Rotated key for sensitive user data');

Performance Considerations:
- Encrypted columns cannot be effectively indexed (only exact matches would work)
- Queries that filter or sort on encrypted columns will be slower
- Consider encryption only for sensitive data that doesn't require indexing or searching
- For high-performance requirements, consider using TDE instead or alongside CLE

Security Best Practices:
- Rotate encryption keys regularly
- Limit decrypt privileges to only the necessary roles
- Maintain secure backups of encryption keys
- Monitor access to decryption functions
- Consider implementing additional security measures like data masking
*/
