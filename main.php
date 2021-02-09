<?php

	// Include statements for other .php files.
	require_once 'login.php';
	define("TABLE1", 'users');
	define("TABLE2", 'putative_infected_files');

	/** Prepare the database. */
	// Connect to our MySQL user.
	$conn = new mysqli($hn, $un, $pw);
	if ($conn->connect_error) die (mysql_fatal_error("The MySQL credentials were invalid."));

	// Create database if it doesn't exist.
	if ($conn->select_db($db) == false) {
		$conn->query("CREATE DATABASE IF NOT EXISTS " . $db);
	}

	// Use the database.
	$conn->select_db($db);
	if ($conn->connect_error) die (mysql_fatal_error("Could not connect to the database."));

	/** If table of registered users doesn't exist yet, create it. */
	// If users table doesn't yet exist, create it.
	$table = TABLE1;
	$result = $conn->query("DESCRIBE $table");
	if (!$result) {
		$result = create_table($conn, $table);
		if (!$result) {
			die (mysql_fatal_error("New " . TABLE1 . " table could not be created."));
		}
	}

	// If putative infected files table doesn't yet exist, create it.
	$table = TABLE2;
	$result = $conn->query("DESCRIBE $table");
	if (!$result) {
		$result = create_table($conn, $table);
		if (!$result) {
			die (mysql_fatal_error("New " . TABLE2 . " table could not be created."));
		}
	}

	// Start the session. If inactive for 5 minutes, it is timed-out.
	ini_set('session.gc_maxlifetime', 60 * 5);
	session_start();
	// Prevent session fixation by changing (regenerating) the session id if it is a new session for the user.
	if (!isset($_SESSION['initiated'])) {
		session_regenerate_id();
		$_SESSION['initiated'] = 1;
	}
	// Assert that the user maintains the exact same ip and browser for the session to prevent session hijacking.
	if (isset($_SESSION['secure'])) {
		if ($_SESSION['secure'] != hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'])){
			destroy_session_and_data();
			die ("<p><a href=main.php>We've run into an error: Click here to log back in.</a></p>");
		}
	}

	// If no current session, show login/registration form so that they can begin one.
	if (empty($_SESSION['un'])) {

		// Display HTML form for registering or login.
		if (!isset($_SESSION['registration']) || ($_SESSION['registration'] == false)) {
			$result = displayLoginForm($conn);
			if (empty($result)) {
				echo "You must log in to see your account's contents. If you don't have an account, please register one below.";
			} else {
				echo "You have successfully logged in.";
				$currentUser = $result;
			}
		}
		else {
			displayRegistrationForm($conn);
		}
	}

	else {
		$currUser = $_SESSION['un'];
		$isAdmin = $_SESSION['is_admin'];
		/** Show the admin a file input field that adds suspected file signatures to the putative infected files DB. */
		if ($isAdmin) {
			displayAdminFileUploader($conn);
		}
		/** Show the user a file input field that validates whether or not the file is infected.*/
		else {
			// Display the file uploader along with all uploaded files for current user.
			displayUserFileUploader($conn);
		}
		displayLogoutButton();
	}

	/** User Credential Functions */
	// Adds the user to the users database. If failed to add to database, return false.
	function add_user($conn, $un, $pw, $isAdmin) {
		$un = sanitize($conn, $un);
		$pw = sanitize($conn, $pw);
		$pwArr = encrypt($pw);
		if ($pwArr == null) {
			return false;
		}
		$query = "INSERT INTO " . TABLE1 . " VALUES('$un', '$pwArr[0]', '$pwArr[1]', '$pwArr[2]', '$isAdmin')";
		$result = $conn->query($query);
		if (!$result) {
			return false;
		}
		return true;
	}

	// Encrypts a password with a salt and a hash, then returns the encrypted password and its salts as an array.
	// Returns false if failed to generate an encrypted password token.
	function encrypt($pw) {
		try {
			$presalt = bin2hex(random_bytes(16));
			$postsalt = bin2hex(random_bytes(16));
		} catch (Exception $e) {
			return null;
		}
		// Concatenate the salts.
		$pw = $presalt . $pw . $postsalt;
		// Hash the salted password.
		$pw = hash('ripemd128', $pw);
		// Return the encrypted password token along with the salts used for later decrypting.
		return array($pw, $presalt, $postsalt);
	}

	// Checks if password has required characters.
	function is_password_valid($pw) {
		// Check uppercase
		if (!preg_match('/[A-Z]/', $pw)) {
			return false;
		}
		// Check lowercase
		if (!preg_match('/[a-z]/', $pw)) {
			return false;
		}
		// Check number
		if (!preg_match('/\d/', $pw)) {
			return false;
		}
		// Check length
		if (strlen($pw) < 8) {
			return false;
		}
		return true;
	}

	// Checks if malware name is of correct format.
	function is_malware_name_valid($malware_name) {
		if (strcmp($malware_name, preg_replace("/[^A-Za-z0-9]/", "", $malware_name)) == 0) {
			return true;
		}
		return false;
	}

	/** MySQL Querying Functions */
	// Create one of two designated MySQL tables. Returns false if failed query.
	function create_table($conn, $table) {
		$result = null;
		if (strcmp($table, TABLE1) == 0) {
			$query = "CREATE TABLE $table(un VARCHAR(128) NOT NULL, 
										pw VARCHAR(128) NOT NULL, 
										presalt VARCHAR(128) NOT NULL,
										postsalt VARCHAR(128) NOT NULL,
										is_admin BOOLEAN NOT NULL,
										PRIMARY KEY(un))";
			$result = $conn->query($query);
		} else if (strcmp($table, TABLE2) == 0) {
			// Signature = sequence of 20 bytes after header of file.
			$query = "CREATE TABLE $table(malware_name VARCHAR(128) NOT NULL, 
										byte_signature CHAR(20) NOT NULL,
										un VARCHAR(128) NOT NULL, 
										id SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
										PRIMARY KEY(id))";
			$result = $conn->query($query);
		}
		if (!$result) {
			return false;
		}
		return true;
	}

	// Queries a given table for all rows corresponding to a given username.
	// Returns -1 if username contains invalid characters, 0 if no rows were found, query result if successful.
	function search_by_username($conn, $table, $un) {
		$un = sanitize($conn, $un);
		if (empty($un)) {
			return -1;
		}
		$query = "SELECT * FROM $table WHERE un='$un'";
		$result = $conn->query($query);
		if (!$result || $result->num_rows == 0) {
			return 0;
		}
		return $result;
	}

	// Adds the file signature to the putative infected files database. If failed to add to database, return false.
	function add_file_signature($conn, $malwareName, $fileSignature, $un) {
		$malwareName = sanitize($conn, $malwareName);
		$fileSignature = sanitize($conn, $fileSignature);
		$query = "INSERT INTO " . TABLE2 . " VALUES('$malwareName', '$fileSignature', '$un', null)";
		$result = $conn->query($query);
		if (!$result) {
			return false;
		}
		return true;
	}

	// Displays all contents corresponding to a given user.
	function display_contents($conn, $un) {
		// Fetch corresponding rows in contents database.
		$result = search_by_username($conn, TABLE2, $un);
		if (empty($result)) {
			// Do nothing.
		}
		else if ($result->num_rows) {

			// Display them on the webpage.
			echo "<table>";
			echo "<tr><td>|Malware Name</td><td>|File Signature</td></tr>";
			for ($i = 0; $i < $result->num_rows; $i++) {
				$row = $result->fetch_array(MYSQLI_NUM);
				$malwareName = $row[0];
				$fileSignature = $row[1];
				echo "<tr><td>|$malwareName</td><td>|$fileSignature</td></tr>";
			}
			echo "</table><br><br>";
			$result->close();
		}
	}

	/** Sanitization Functions */
	// Sanitize the HTML off a string value.
	function sanitizeHTML($conn, $input) {
		if (get_magic_quotes_gpc()) {
			$input = stripslashes($input);
		}
		$input = strip_tags($input);
		$input = htmlentities($input);
		return $input;
	}

	// Fully sanitize a string of both PHP and HTML.
	function sanitize($conn, $input) {
		$input = sanitizeHTML($conn, $input);
		return $conn->real_escape_string($input);
	}

	/** Error Handling Functions */
	function mysql_fatal_error($msg) {
		echo <<<_END
    It seems like an error has occurred in querying or starting up mySQL. <br>
    The error is as follows:
    <i><p>$msg</p></i>
    Please try again later.  
_END;
	}

	/** Session Security Functions */
	function destroy_session_and_data() {
		$_SESSION = array();
		session_destroy();
	}

	/** Virus Checking Functions */
	function check_for_infection($conn, $fileContents) {
		$isInfected = false;
		// If no input, return false by default.
		if (empty($fileContents)) {
			return false;
		}
		// Get all putative infected file signatures from database.
		$query = "SELECT * FROM " . TABLE2;
		$result = $conn->query($query);
		// If no malware in database, return false by default.
		if (empty($result)) {
			return false;
		}
		else if ($result->num_rows) {
			// Display all malware infections in the file, if they exist.
			echo "<table>";
			echo "<tr><td>|Malware Name</td><td>|File Signature</td></tr>";
			for ($i = 0; $i < $result->num_rows; $i++) {
				$row = $result->fetch_array(MYSQLI_NUM);
				$malwareName = $row[0];
				$fileSignature = $row[1];
				if (strpos($fileContents, $fileSignature) !== false) {
					echo "<tr><td>|$malwareName</td><td>|$fileSignature</td></tr>";
					$isInfected = true;
				}
			}
			echo "</table><br><br>";
			return $isInfected;
		}

	}

	/** HTML Webpage Displaying Functions */
	// Displays the registration form.
	function displayRegistrationForm($conn) {
		echo
		<<<_END
<script src="validate_fields.js"></script>
<html>
<body>
<h1>Registration</h1>
<form action='main.php' method='post'><pre>
<table>
<tr><td align="right">New Username</td> <td align="left"><input type="text" name="un_reg"></td></tr>
<tr><td align="right">Password</td> <td align="left"><input type="text" name="pw1_reg"></td></tr>
<tr><td align="right">Retype Password</td> <td align="left"><input type="text" name="pw2_reg"></td></tr>
<tr><td align="right">Admin Account</td> <td align="left"><input type="checkbox" name="is_admin"></td></tr>
</table>
<input type="button" value="Sign Up" name="btn_reg" onClick="validateRegistrationForm(this.form); this.form.submit()">
<input type='submit' value="Back to Login" name="btn_back"><br><br>
</pre></form></body>
</html>
_END;
		// Check if back button was pressed.
		if (!empty($_POST['btn_back'])) {
			$_SESSION['registration'] = false;
			die ("<p><a href=main.php>Click here to go back to login.</a></p>");
		}
		// If back button wasn't pressed and form was still submitted, assume sign up button was pressed.
		else if (!empty($_POST['un_reg']) && !empty($_POST['pw1_reg']) && !empty($_POST['pw2_reg'])) {
			$un_reg = $_POST['un_reg'];
			$pw_reg = $_POST['pw1_reg'];
			$is_admin = 0;
			if (isset($_POST['is_admin'])) {
				$is_admin = 1;
			}

			$validCredentials = true;

			$validPw = is_password_valid($pw_reg);
			$validCredentials = $validCredentials && $validPw;
			if (!$validPw) {
				echo "Please include 1 uppercase, 1 lowercase, 1 number, and 8 characters in your password.<br><br>";
			}

			// Check if username is unique; no duplicate usernames in users database.
			$result = search_by_username($conn, TABLE1, $un_reg);
			$validCredentials = $validCredentials && ($result == 0);
			if (!is_int($result)) {
				echo "This username already exists. Please try another username.<br><br>";
			} else if ($result == -1) {
				echo "Invalid username was inputted.<br><br>";
			}

			// Check if password was entered correctly both times.
			$pwMatch = (strcmp($pw_reg, $_POST['pw2_reg']) == 0);
			$validCredentials = $validCredentials && $pwMatch;
			if (!$pwMatch) {
				echo "Given passwords do not match. Please check your spelling and try again.<br><br>";
			}

			// If credentials pass all tests, go ahead and add the user to the database.
			if ($validCredentials) {
				$result = add_user($conn, $un_reg, $pw_reg, $is_admin);
				if (!$result) {
					die (mysql_fatal_error("New user could not be created.<br><br>"));
				} else {
					echo "Your new user has been added to the database. <br><br>";
				}
			}
		}
	}

	// Displays the login form. Returns the current user if the user logs in successfully. Otherwise, returns null.
	function displayLoginForm($conn) {
		echo
		<<<_END
<script src="validate_fields.js"></script>
<html>
<head><title>Online Virus Check: Login</title></head>
<body>
<h1>Log In</h1>
<form action='main.php' method='post' id="login_form"><pre>
<table>
<tr><td align="right">Username</td> <td align="left"><input type="text" name="un_login"></td></tr>
<tr><td align="right">Password</td> <td align="left"><input type="text" name="pw_login"></td></tr>
</table>
<input type="button" value="Log In" name="btn_login" onClick="validateLoginForm(this.form); this.form.submit()">
<input type="submit" value="Register an Account" name="btn_to_reg"><br><br>
</pre></form></body>
</html>
_END;
		// Check if register an account button was pressed.
		if (!empty($_POST['btn_to_reg'])) {
			$_SESSION['registration'] = true;
			die ("<p><a href=main.php>Click here to go to registration form.</a></p>");
		}
		// If register and account button wasn't pressed and form was still submitted, assume login button was pressed.
		else if (!empty($_POST['un_login']) && !empty($_POST['pw_login'])) {
			$login_error_msg = "Username or password was incorrect.<br><br>";
			$un_login = sanitize($conn, $_POST['un_login']);
			$pw_login = sanitize($conn, $_POST['pw_login']);

			// Search for username in users database and check if the password is correct.
			$result = search_by_username($conn, TABLE1, $un_login);
			if (!$result) {
				echo $login_error_msg;
				return null;
			} else if ($result->num_rows) {
				$row = $result->fetch_array(MYSQLI_NUM);
				$result->close();
				$isAdmin = $row[4];
				$presalt = $row[2];
				$postsalt = $row[3];
				$token = hash('ripemd128', "$presalt$pw_login$postsalt");
				if ($token == $row[1]) {
					$_SESSION['un'] = $un_login;
					$_SESSION['pw'] = $pw_login;
					$_SESSION['is_admin'] = $isAdmin;

					// Assert that the session maintains its current IP and web browser to prevent hijacking.
					$_SESSION['secure'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);

					// Force the user to reload the page.
					if ($isAdmin) {
						echo "You have successfully logged in with admin account '$un_login'.";
					}
					else {
						echo "You have successfully logged in with user account '$un_login'.";
					}
					die ("<p><a href=main.php>Click here to continue</a></p>");
				}
			}
			echo $login_error_msg;
			return null;
		}
		return null;
	}

	// Displays a logout button.
	function displayLogoutButton() {
		echo
		<<<_END
<html>
<body>
<form method='post' action='main.php' enctype='multipart/form-data' >                    
<input type='submit' value="Log Out" name="btn_logout" /> <br>
</form>
</body>
</html>
_END;

		if (!empty($_POST['btn_logout'])) {
			destroy_session_and_data();
			die ("<p><a href=main.php>You have been logged out. Click here to log back in.</a></p>");
		}
	}

	// Displays the contents input form, taking the name of the contents and a .txt containing the contents.
	function displayUserFileUploader($conn) {
		echo
		<<<_END
<script src="validate_fields.js"></script>
<html>
<head><title>Online Virus Check: User Upload</title></head>
<body>
<h1>Check File for Infection</h1>
<p>Please upload the file you would like to test for a malware infection.</p>
<form method='post' action='main.php' enctype='multipart/form-data'>                 
<label for='file'>File:</label> <input type='file' name='file' size="10" /> <br> <br>             
<input type='submit' value="Check if Infected" name='submit_btn' /> <br>
</form>
</body>
</html>
_END;

		if (isset($_POST['submit_btn']) && file_exists($_FILES['file']['tmp_name'])) {

			// Check if a valid .txt file was uploaded.
			$contents = getFileContents($_FILES);
			if ($contents == null) {
				echo "Please upload a valid .txt file.<br><br>";
				return -1;
			}

			// Get uploaded file name.
			$fileName = strtolower(preg_replace("/[^A-Za-z0-9.]/", "", $_FILES['file']['name']));

			// Check putative infected files database to see if uploaded file contains any of them.
			if (check_for_infection($conn, $contents)) {
				echo "Your uploaded file '$fileName' is infected with malware. :( <br><br>";
			}
			else {
				echo "Your uploaded file '$fileName' is clean of malware! :) <br><br>";
			}
		}
		else {
			echo "Please upload a .txt file.<br><br>";
			return -1;
		}
	}

	// Displays the contents input form, taking the name of the contents and a .txt containing the contents.
	function displayAdminFileUploader($conn) {
		echo
		<<<_END
<script src="validate_fields.js"></script>
<html>
<head><title>Online Virus Check: Admin Upload</title></head>
<body>
<h1>Upload a Malware File</h1>
<p>Please input the malware name and its associated malware file.</p>
<form method='post' action='main.php' enctype='multipart/form-data' onSubmit="return validateAdminForm(this)">            
<label for='file_name'>Malware Name:</label> <input type='text' name='file_name'/> <br>           
<label for='file'>Malware File:</label> <input type='file' name='file' size="10" /> <br> <br>             
<input type='submit' value="Add to Malware Database" name='submit_btn' /> <br>
</form>
</body>
</html>
_END;

		if (!empty($_POST['file_name']) && file_exists($_FILES['file']['tmp_name'])) {

			// Check if a valid name was input.
			$malwareName = sanitize($conn, $_POST['file_name']);
			if (!is_malware_name_valid($malwareName)) {
				echo "Invalid name, please try again. Only alphanumerical characters allowed.<br><br>";
				return -1;
			}

			// Check if a valid .txt file was uploaded.
			$malwareContents = getFileContents($_FILES);
			$malwareSignature = null;
			if ($malwareContents == null) {
				echo "Please upload a valid .txt file.<br><br>";
				return -1;
			}
			else {
				// Get the file's signature (first 20 characters)
				$malwareSignature = substr($malwareContents, 0, 20);
			}

			// Add the malware name and the signature of the malware file to the putative infected files database.
			$result = add_file_signature($conn, $malwareName, $malwareSignature, $_SESSION['un']);
			if ($result) {
				echo "$malwareName has been successfully added to the database of putative infected file signatures.";
			}
		}
		else {
			echo "Please fill out the name field and upload a .txt file.<br><br>";
			return -1;
		}
	}


	// Retrieves contents from uploaded file and sanitizes it.
	function getFileContents($fileInfoArray) {
		echo "<body><html>";

		// If file is uploaded (exists), do the following.
		if ($fileInfoArray) {

			$name = $fileInfoArray['file']['name'];
			$tmpName = $fileInfoArray['file']['tmp_name'];
			$ext = $fileInfoArray['file']['type'];

			// Sanitize the file name.
			$name = strtolower(preg_replace("/[^A-Za-z0-9.]/", "", $name));
			// Sanitize the temporary name; already safe, but good habit to sanitize all super variables. Retain ':', '/', '\' for temporary name's path.
			$tmpName = strtolower(preg_replace("/[^A-Za-z0-9.:\/\\\\]/", "", $tmpName));

			// Validate that the file is a .txt style file.
			if ($ext != "text/plain") {
				echo "'$name' is not of an accepted file type. (Expected: text file)<br><br>";
			} else {
				return file_get_contents($tmpName);
			}
		}
		echo "No file has been uploaded.<br><br>";
		return null;
	}


