# SMTP Server Authentication Order and Best Practices

## Summary of Fixes (June 2025)

This document describes the authentication logic and order for the SMTP server, as well as the recent fixes applied to ensure correct sender authentication and IP whitelisting behavior.

### What Was Fixed
- **Authentication Response:**
  - The server now immediately responds with an SMTP error (e.g., `535 Authentication failed`) if the username or password is incorrect, instead of hanging the session. This is achieved by returning `AuthResult(success=False, handled=False, message='535 Authentication failed')` from the authenticator, allowing the aiosmtpd framework to send the error to the client.
- **No Forced Connection Close:**
  - The server does not forcibly close the connection after failed authentication, but lets the SMTP client decide whether to retry or quit, as per SMTP protocol best practices.
- **AUTH on Both Ports:**
  - Both the plain SMTP port (`smtp_port`) and the secure TLS port (`smtp_tls_port`) now advertise and allow authentication (AUTH LOGIN/PLAIN). IP whitelist fallback is also available on both ports.

## Authentication Order and Logic

1. **Connection Handling**
   - If a client connects to the plain SMTP port, both AUTH and IP whitelisting are available.
   - If a client connects to the TLS SMTP port, the connection is immediately secured with TLS. Both AUTH and IP whitelisting are available.

2. **Sender Authentication (Username/Password)**
   - When a client issues the AUTH command (LOGIN or PLAIN) on either port:
     - The server checks the username and password against the database.
     - If valid, the session is marked as authenticated and the sender can send as their own address or, if permitted, as any address in their domain.
     - If invalid, the server responds with `535 Authentication failed` and does not hang the session.

   **Code Snippet for Immediate Authentication Failure Response:**
   ```python
   # In email_server/auth.py
   def __call__(self, server, session, envelope, mechanism, auth_data):
       # ...existing code...
       if not isinstance(auth_data, LoginPassword):
           logger.warning(f'Invalid auth data format: {type(auth_data)}')
           return AuthResult(success=False, handled=False, message='535 Authentication failed')
       # ...existing code...
       try:
           sender = get_sender_by_email(username)
           if sender and check_password(password, sender.password_hash):
               # ...success logic...
               return AuthResult(success=True, handled=True)
           else:
               # ...failure logging...
               return AuthResult(success=False, handled=False, message='535 Authentication failed')
       except Exception as e:
           # ...error logging...
           return AuthResult(success=False, handled=False, message='451 Internal server error')
   ```
   - Returning `handled=False` ensures the SMTP client is immediately informed of the failure and does not hang.

3. **IP Whitelisting (Secondary/Fallback)**
   - If no AUTH is provided, the server checks if the client's IP is whitelisted for the target domain.
   - If the IP is whitelisted, the session is authorized to send for that domain.
   - If not, the server rejects the mail transaction.

## Best Practices for Future Development

- **Always return `handled=False` in `AuthResult` for failed authentication** to ensure the SMTP client receives an error and the session does not hang.
- **Advertise AUTH on both the plain SMTP and TLS ports**; allow both user authentication and IP whitelist fallback.
- **Do not use or advertise STARTTLS** on any port if only direct TLS is desired.
- **Log all authentication attempts** (success and failure) for auditing and troubleshooting.
- **Keep authentication and IP whitelisting logic modular** for easy updates and security reviews.

## Example Client Setup
- For user authentication, connect to either the plain SMTP port (e.g., 25 or 4025) or the TLS port (e.g., 40587) and use the correct username and password.
- For IP whitelisting, connect from an authorized IP to either port; no authentication is required, but the sender must be allowed for the domain.

---

**This document should be updated if the authentication logic or port usage changes in the future.**
