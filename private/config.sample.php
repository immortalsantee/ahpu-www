<?php
// Ahpu admin config. This folder must never be public (see private/.htaccess).
// SETUP_KEY is only used once, to create the first admin password at /admin.
// After the password is set, setup is disabled automatically. You may blank it then.
return [
    'setup_key'        => 'PUT-A-LONG-RANDOM-STRING-HERE',
    'session_minutes'  => 30,   // auto sign-out after this many idle minutes
    'max_attempts'     => 5,    // wrong passwords allowed per IP ...
    'lock_minutes'     => 15,   // ... before that IP is locked for this long
    'max_upload_mb'    => 5,
    'logo_size'        => 400,  // logos are resized to fit this many pixels
];
