USE AcademyDB_Extended;

-- Generate initial encryption key
CALL sp_GenerateColumnEncryptionKey('InitialKey', 365, 'Initial encryption key for sensitive data');

-- Migrate Students table to use encryption
CALL sp_MigrateToColumnEncryption('Students', 'Email,Contact,AdditionalInfo', 'InitialKey');

-- Migrate Faculty table to use encryption
CALL sp_MigrateToColumnEncryption('Faculty', 'Email,Contact,AdditionalInfo', 'InitialKey');

-- Migrate Admin table to use encryption
CALL sp_MigrateToColumnEncryption('Admin', 'Email,Contact,AdditionalInfo', 'InitialKey');

-- Create decryption views
CALL sp_CreateDecryptionView('Students');
CALL sp_CreateDecryptionView('Faculty');
CALL sp_CreateDecryptionView('Admin');

-- Grant decrypt privileges to appropriate roles
CALL sp_GrantDecryptPrivilege('AdminRole', 'Students', 'Email');
CALL sp_GrantDecryptPrivilege('AdminRole', 'Students', 'Contact');
CALL sp_GrantDecryptPrivilege('AdminRole', 'Students', 'AdditionalInfo');

CALL sp_GrantDecryptPrivilege('AdminRole', 'Faculty', 'Email');
CALL sp_GrantDecryptPrivilege('AdminRole', 'Faculty', 'Contact');
CALL sp_GrantDecryptPrivilege('AdminRole', 'Faculty', 'AdditionalInfo');

CALL sp_GrantDecryptPrivilege('AdminRole', 'Admin', 'Email');
CALL sp_GrantDecryptPrivilege('AdminRole', 'Admin', 'Contact');
CALL sp_GrantDecryptPrivilege('AdminRole', 'Admin', 'AdditionalInfo'); 