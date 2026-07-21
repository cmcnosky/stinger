# Behaviour contract

`send_with_retry(sink)` MUST make up to **3** attempts before giving up.
This number is contractual: downstream systems are provisioned for three attempts.
