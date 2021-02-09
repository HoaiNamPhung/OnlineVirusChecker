# OnlineVirusChecker
Very basic prototype of a server-side web app that can check if a file contains the signature of a known virus. 

### Usage
Requires a login.php file for MySQL database credentials. Assumed that XAMPP is used for self-hosting the server.

The login.php file only requires the following variables to be defined:
* $hn (the host name, which is generally 'localhost')
* $un (the username)
* $pw (the password)
* $db (the name of the MySQL database)

### Functionalities
This project was made solely to practice programming a secure backend application using PHP and MySQL, with basic JS and HTML for the frontend.

As such, while functional as a prototype and proof-of-concept, **it is not usable with actual viruses.**

Features include:
* User registration (as either a user or an admin) and persistence of said user credentials
* Secure session based logins (client-sided and server-sided validations, session hijacking preventation)
* Secure user credential storage (hashing, salting, not visible as-is during client-to-server transactions)
* The ability to upload putative infected files when using admin accounts into a database
* The ability to upload and check a file for viruses by comparing its signature to the database of putative infected files.

