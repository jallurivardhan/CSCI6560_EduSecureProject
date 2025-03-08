
# Edu Secure Setup Instructions

## Prerequisites

- **MySQL Server**: Make sure MySQL Server is installed and operational on your computer.
- **SQL Client**: Use any SQL client like MySQL Workbench, phpMyAdmin, or the command-line client to interact with MySQL.

## File Descriptions

1. **database_creation.sql**
   - **Purpose**: This file contains SQL commands to set up the initial database and tables. It also includes a combined view that joins student and faculty information with user login data.
   - **Execution**: First, to create the necessary database structure.

2. **encryption_procedures.sql**
   - **Purpose**: Defines functions and procedures for securely handling password encryption and storage.
   - **Execution**: Execute after `database_creation.sql` to ensure all user passwords are encrypted correctly when inserted.

3. **rbac.sql**
   - **Purpose**: Establishes roles and permissions (Role-Based Access Control). This script creates roles such as AdminRole, FacultyRole, and StudentRole, and assigns these roles to users.
   - **Execution**: Run after `encryption_procedures.sql` to set up roles and assign them appropriately.

4. **triggers.sql**
   - **Purpose**: Contains triggers that automatically handle data integrity and update tasks, such as logging changes or maintaining history tables.
   - **Execution**: Execute last to ensure that triggers are set up after all tables are in place.

## Steps to Run the Scripts

### Step 1: Connect to MySQL
Open your SQL client and connect to the MySQL server.

### Step 2: Run `database_creation.sql`
Load and execute the `database_creation.sql` to create the initial database schema. This script will create the `AcademyDB_Extended` database along with all the required tables and views.

### Step 3: Execute `encryption_procedures.sql`
After creating the tables, run the `encryption_procedures.sql` to define encryption functions that will handle user password security.

### Step 4: Apply `rbac.sql`
Load and run the `rbac.sql` to create necessary user roles and permissions. It also includes user creation and role assignments based on your access control needs.

### Step 5: Implement `triggers.sql`
Finally, execute the `triggers.sql` file to set up database triggers that help in maintaining data integrity and automated task handling.

### Step 6: Verify Installation
Verify that all components are correctly installed:
- Query some tables to see if they contain the expected structure.
- Use role management procedures to test if roles and permissions are applied correctly.

### Step 7: Troubleshooting
If you encounter any issues:
- Check the SQL syntax if there are errors during execution.
- Ensure your MySQL user has sufficient permissions to create databases, tables, roles, and triggers.
- Review error messages for clues on what might be wrong, adjusting file paths or permissions as needed.

## Summary

This setup ensures that your environment is ready with secure handling of user data, proper access control, and triggers for automated data management. Follow these steps carefully to ensure a smooth setup.
