# SQL injection (SQLi)

SQL injection happens when an attacker is able to manipulate with database queries done by an application. This allows the attacker to gain access to data, update or delete data. SQLi is very much a threat for escalation of privilege as well.

SQLi can be detected using systematic tests against various entry points in the application (entry points are places where the attacker is able to supply input). Typically the following are ways to look for SQLi:

- Submit `'` and look for errors (This character will finish an argument of an SQL query)
- Boolean conditions: `OR 1=1` or similar. Does not have to evaluate to true.
- Timing attacks. Look these up on Hacktricks.xyz (they are often framework specific)

**Note**: SQLi is often mitigated by sanitizing input and using prepared statements

This part of the learning path, was already completed. See other writeups.