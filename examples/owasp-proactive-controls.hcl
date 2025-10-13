spec_version = "0.1.15"

// These are from https://github.com/OWASP/www-project-proactive-controls/tree/7622bebed900a6a5d7b7b9b01fb3fe2b0e695545/v3/en

component "control" "owasp-secframework-trustedlibs" {
  description = "Libraries and frameworks are from trusted sources that are actively maintained and widely used by many applications"
}

component "control" "owasp-secframework-3rdpartycat" {
  description = "3rd party libraries are maintained in an inventory catalog"
}

component "control" "owasp-secframework-maintain3rdparty" {
  description = "[OWASP Dependency Check](https://www.owasp.org/index.php/OWASP_Dependency_Check) or [Retire.JS](https://retirejs.github.io/retire.js/) are used to keep 3rd party components up to date"
}

component "control" "owasp-secframework-encapslibs" {
  description = "When using 3rd party libraries, necessary capabilities are enapsulated and only expose required behavior"
}

component "control" "owasp-secdb-secqury" {
  description = "All untrusted input into database queries is handled with query parameterisation. As per https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet"
}

component "control" "owasp-secdb-secconfig" {
  description = "The DBMS' configuration is hardened as per https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html#database-configuration-and-hardening"
}

component "control" "owasp-secdb-seccomm" {
  description = "All database connections occur over authenticated and encrypted channels, and never in cleartext"
}

component "control" "owasp-encoding-output" {
  description = "All dynamic output in the application uses contextual output encoding"
}

component "control" "owasp-validinput-syntax" {
  description = "All untrusted input is syntactically validated. For example, if an input is expecting a number, then the input should be validated as a number"
}

component "control" "owasp-validinput-semantic" {
  description = "All untrusted input is semanteically validated, where applicable. For example, a start date must be before an end date"
}

component "control" "owasp-validinput-allowlist" {
  description = "Where possible, the use of allowlists are used to validate untrusted inputs. Where denylists are used, these are more focused on abuse monitoring"
}

component "control" "owasp-validinput-serverside" {
  description = "All untrusted input is validated on the server-side, where possible. Client-side validation may be used for UX only"
}

component "control" "owasp-identity-passwordreq" {
  description = "Passwords requirements meet those documented by [OWASP](https://github.com/OWASP/www-project-proactive-controls/blob/7622bebed900a6a5d7b7b9b01fb3fe2b0e695545/v3/en/c6-digital-identity.md)"
}

component "control" "owasp-identity-passwordreset" {
  description = "Password reset mechanism is implemented as per https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet"
}

component "control" "owasp-identity-passwordstorage" {
  description = "Password storage mechanism is implemented as per https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet"
}

component "control" "owasp-identity-mfa" {
  description = "Multi-factor Authentication (MFA) is available for users to configure"
}

component "control" "owasp-access-centralacl" {
  description = "All requests are handled by a unified, central authentication and authorisation framework or filter"
}

component "control" "owasp-access-denydefault" {
  description = "By default, all authorisation checks will deny, by default"
}

component "control" "owasp-access-leastprivilege" {
  description = "All permission sets are configured with least-privilege in mind"
}

component "control" "owasp-access-logs" {
  description = "All access control failures are logged"
}

component "control" "owasp-dataprotection-transit" {
  description = "TLS, or other cryptographic protocols, are used for all data as it is transmitted over networks"
}

component "control" "owasp-dataprotection-atrest" {
  description = "All sensitive data is encrypted at rest"
}

component "control" "owasp-dataprotection-keys" {
  description = "All cryptographic keys are protected from unauthorised access, and are securly rotated"
}

component "control" "owasp-dataprotection-secretsdetection" {
  description = "Secrets are scanned for in source code using a tool like [TruffleHog](https://github.com/dxa4481/truffleHog)"
}

component "control" "owasp-dataprotection-secretsstorage" {
  description = "Secrets are stored in a secrets management solution, and not hard coded in source code"
}

component "control" "owasp-logging-encoding" {
  description = "Encoding and validation are performed on logging systems to reduce the likelihood of [log injection](https://www.owasp.org/index.php/Log_Injection) attacks"
}

component "control" "owasp-logging-sensitive" {
  description = "Logs do not include sensitive data"
}

component "control" "owasp-logging-protection" {
  description = "Logs access is restricted to authorised users only, and are stored in write-once, read-many (WORM) style solutions"
}

component "control" "owasp-errors-infoleak" {
  description = "Error messages are not verbose on public interfaces"
}
