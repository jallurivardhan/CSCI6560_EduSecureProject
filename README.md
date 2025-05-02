# AcademyDB Security System

A Flask-based security management system for academic database administration implementing multiple database security features.

## Features

- **Role-Based Access Control (RBAC)**
  - Admin, Faculty, and Student roles
  - Granular permission management
  - Role-based data access control

- **Data Security**
  - Column-level encryption for sensitive data
  - Dynamic data masking based on user roles
  - Comprehensive audit logging
  - Automated security triggers

- **Database Management**
  - Automated backup and restore functionality
  - Security metrics dashboard
  - User activity monitoring
  - Real-time security alerts

## Project Structure

```
.
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── Sql/                  # SQL scripts and procedures
├── static/              # Static assets (CSS, JS, images)
└── Template/            # HTML templates
```

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python app.py
   ```

## Usage

1. Access the web interface at `http://localhost:5000`
2. Login credentials:
   - Admin: Admin1
   - Faculty: Faculty1
   - Student: Student1

## Security Features

### RBAC Implementation
- AdminRole: Full system access
- FacultyRole: Limited access to student data
- StudentRole: Access to personal data only

### Data Protection
- AES encryption for sensitive fields
- Dynamic data masking
- Comprehensive audit trails
- Automated security triggers

### Monitoring
- Real-time user activity tracking
- Security metrics dashboard
- Automated backup management
- Security test suite

