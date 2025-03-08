
-- Create Database and set active database
CREATE DATABASE IF NOT EXISTS AcademyDB_Extended;
USE AcademyDB_Extended;

-- KeyVault Table Creation
CREATE TABLE IF NOT EXISTS KeyVault (
    KeyName         VARCHAR(50)   PRIMARY KEY,
    EncKey          VARBINARY(8000),
    KeyCreationTime DATETIME      DEFAULT CURRENT_TIMESTAMP,
    KeyStatus       ENUM('Active', 'Inactive') DEFAULT 'Active',
    ExpirationDate  DATETIME      DEFAULT NULL,
    LastUpdated     DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Master Key Insertion
INSERT IGNORE INTO KeyVault (KeyName, EncKey, ExpirationDate) 
VALUES ('MainKey', UNHEX(SHA2('MasterKeyPassword@123', 256)), DATE_ADD(NOW(), INTERVAL 1 YEAR));

-- Encryption Key Management Procedures
DELIMITER //

CREATE PROCEDURE sp_RotateEncryptionKey(
    IN p_KeyName VARCHAR(50),
    IN p_NewKeyPassword VARCHAR(100),
    IN p_NewExpiration DATETIME
)
BEGIN
    DECLARE newKey VARBINARY(8000);
    SET newKey = UNHEX(SHA2(p_NewKeyPassword, 256));
    UPDATE KeyVault 
    SET EncKey = newKey, 
        ExpirationDate = p_NewExpiration,
        KeyCreationTime = NOW(),
        KeyStatus = 'Active'
    WHERE KeyName = p_KeyName;
    SELECT CONCAT('Encryption key ', p_KeyName, ' rotated successfully at ', NOW()) AS Message;
END//

CREATE PROCEDURE sp_DeactivateEncryptionKey(
    IN p_KeyName VARCHAR(50)
)
BEGIN
    UPDATE KeyVault 
    SET KeyStatus = 'Inactive'
    WHERE KeyName = p_KeyName;
    SELECT CONCAT('Encryption key ', p_KeyName, ' deactivated successfully at ', NOW()) AS Message;
END//

CREATE PROCEDURE sp_GetEncryptionKeyStatus(
    IN p_KeyName VARCHAR(50)
)
BEGIN
    SELECT KeyName, KeyStatus, ExpirationDate, KeyCreationTime, LastUpdated 
    FROM KeyVault 
    WHERE KeyName = p_KeyName;
END//

DELIMITER ;
