# Sumpidy

Author: @xntrik

## Threat Scenarios

### Threat

threaty threat

> STRIDE: Spoofing, Elevation Of Privilege

#### Controls


##### AWS Orgs


> Implemented: ✅

AWS accounts are managed with [AWS Organisations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html#features)

|    |    |
| -- | -- |
| Risk Reduction | 40 |
##### Root Account Lockdown


> Implemented: ✅

The root user is only used by exception, and has [MFA](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa) enabled

|    |    |
| -- | -- |
| Risk Reduction | 50 |
### Threat

Something else

#### Controls


##### Prevent Leakage

> Implemented: ❌

Error messages are not verbose on public interfaces

|    |    |
| -- | -- |
| Risk Reduction | 10 |
##### Do the thing

> Implemented: ❌

Yep do it

|    |    |
| -- | -- |
| Risk Reduction | 30 |
##### Do another thing

> Implemented: ❌

Also do this other thing

|    |    |
| -- | -- |
| Risk Reduction | 30 |
##### thing

> Implemented: ❌

This is the new type of control

|    |    |
| -- | -- |
| Risk Reduction | 40 |
### Threat

Something else that is also equally as bad

#### Controls


##### trusted libraries

> Implemented: ❌

Libraries and frameworks are from trusted sources that are actively maintained and widely used by many applications

|    |    |
| -- | -- |
| Risk Reduction | 50 |
| proactive_control | C2 |
| url | https://owasp.org/www-project-proactive-controls/v3/en/c2-leverage-security-frameworks-libraries |

