function validateMalwareName(malwareName) {
    if (malwareName == "") {
        return "No malware name was entered.\n"
    }
    else if (/[^a-zA-Z0-9]/.test(malwareName)) {
        return "Invalid characters used for malware name. (Expected: only alphanumerical).\n";
    }
    return "";
}

// I gave up on validating file input client side for now.
function validateFileInputType(file) {
    if (file.value == "") {
        return "No file was uploaded."
    }
    else if (!file.type.match('text.*')) {
        return "Invalid file type submission. (Expected: text files).\n";
    }
    return "";
}

function validateUsername(un) {
    if (un == "") {
        return "No username was entered.\n"
    }
    return "";
}

function validatePassword(pw1, pw2) {
    if (pw1 == "") {
        return "No password was entered.\n"
    }
    else if (pw1.length < 8) {
        return "Password should be at least 8 characters long.\n"
    }
    else if (!/[a-z]/.test(pw1) || !/[A-Z]/.test(pw1) || !/[0-9]/.test(pw1)) {
        return "Password should at least contain 1 uppercase, 1 lowercase, and 1 number.\n"
    }
    else if (pw1 != pw2) {
        return "Given passwords do not match."
    }
    return "";
}

function validateAdminForm(form) {
    let fail = validateMalwareName(form.file_name.value);
    // fail += validateFileInputType(form.getElementById("file"));

    if (fail == "") {
        return true;
    }
    else {
        alert(fail);
        return false;
    }
}

/**
function validateUserForm(form) {
    fail = validateFileInputType(document.getElementById("file"));

    if (fail == "") {
        return true;
    }
    else {
        alert(fail);
        return false;
    }
}
 */

function validateRegistrationForm(form) {
    let fail = validateUsername(form.un_reg.value);
    fail += validatePassword(form.pw1_reg.value, form.pw2_reg.value);

    if (fail == "") {
        return true;
    }
    else {
        alert(fail);
        return false;
    }
}

function validateLoginForm(form) {
    let fail = "";
    if (form.un_login.value == "") {
        fail += "No username was entered.\n"
    }
    if (form.pw_login.value == "") {
        fail += "No password was entered.\n"
    }

    if (fail == "") {
        return true;
    }
    else {
        alert(fail);
        return false;
    }
}