# API Security Tester

A command-line tool for testing REST API security vulnerabilities.

## Features

- Tests for common API security vulnerabilities:
  - Brute force attacks
  - Missing authentication
  - SQL injection
  - Rate limiting bypass
  - Information disclosure
- Interactive CLI with colorful output
- Detailed vulnerability reports with recommendations

## Installation

\`\`\`bash
# Clone the repository
git clone https://github.com/oattydev/api-security-tester.git
cd api-security-tester

# Install dependencies
npm install

# Link the CLI tool globally
npm link
\`\`\`

## Usage

\`\`\`bash
# Basic usage
api-security-tester scan -u https://api.example.com -e /users,/products

# With authentication token
api-security-tester scan -u https://api.example.com -e /users -a your-auth-token

# Run specific tests
api-security-tester scan -u https://api.example.com -e /login -t brute-force,sql-injection

# Verbose output
api-security-tester scan -u https://api.example.com -e /users -v

# Interactive mode (will prompt for URL and endpoints)
api-security-tester scan
\`\`\`

## Options

- `-u, --url <url>`: API base URL to test
- `-e, --endpoints <endpoints>`: Comma-separated list of API endpoints to test
- `-a, --auth <auth>`: Authentication token (if required)
- `-t, --tests <tests>`: Comma-separated list of tests to run (default: all)
- `-v, --verbose`: Show detailed output

## Security Concepts

### REST API Basics

REST APIs typically support these HTTP methods:
- **GET**: Retrieve resources
- **POST**: Create new resources
- **PUT**: Update existing resources
- **DELETE**: Remove resources

### Authentication Methods

- **JWT (JSON Web Tokens)**: Stateless authentication using signed tokens
- **Session-based**: Server-side session storage with client-side cookies
- **OAuth 2.0**: Authorization framework for third-party access
- **API Keys**: Simple key-based authentication

### OWASP Top 10 API Security Risks

1. **Broken Object Level Authorization**: APIs don't properly validate access to resources
2. **Broken Authentication**: Weak implementation of authentication mechanisms
3. **Excessive Data Exposure**: APIs return more data than necessary
4. **Lack of Resources & Rate Limiting**: No protection against brute force or DoS attacks
5. **Broken Function Level Authorization**: Unauthorized access to functionality
6. **Mass Assignment**: Client-provided data is blindly assigned to objects
7. **Security Misconfiguration**: Insecure default configurations, open cloud storage
8. **Injection**: SQL, NoSQL, command injection attacks
9. **Improper Assets Management**: Exposed debug endpoints, outdated documentation
10. **Insufficient Logging & Monitoring**: Lack of visibility into malicious activities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.