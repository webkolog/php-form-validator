# W-PHP Form Validator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Version:** 1.2 (Form Validator)

**Last Updated:** 2015-07-27

**Compatibility:** PHP 5.4

**Created By:** Ali Candan ([@webkolog](https://github.com/webkolog))

**Website:** [http://webkolog.net](http://webkolog.net)

**Copyright:** (c) 2015 Ali Candan

**License:** MIT License ([http://mit-license.org](http://mit-license.org))

A flexible PHP form validation class with multi-language support and database integration.

## Features

-   **Easy to Use:** Simple and intuitive API for defining validation rules.
-   **Multi-Language Support:** Easily switch between languages for error messages.
-   **Database Integration:** Check for unique values in your database.
-   **Comprehensive Validation Rules:** Supports a wide range of validation rules, including:
    -   Required fields
    -   Matching fields
    -   Unique values
    -   String length (min, max, exact, range)
    -   Numeric values (greater than, less than, range)
    -   Date and time validations
    -   Email, IP, URL, phone number, and more
    -   Regular expressions
-   **Customizable Error Messages:** Define your own error messages or use the built-in multi-language support.
-   **Helper Functions:** Use custom helper functions to preprocess input values.
-   **Flexible Form Methods:** Supports both POST and GET form methods.

## Compatibility and Requirements

* PHP 5.4+
* PDO

## Installation

1.  Copy the `form-validator.php` file and the `languages` folder to your project directory.
2.  Include the `form-validator.php` file in your PHP script:

    ```php
    require_once 'form-validator.php';
    ```

3.  Create language files in the `languages` folder (e.g., `en.php`, `tr.php`).

## Usage

### Basic Example

```php
<?php

require_once 'form-validator.php';

// Example: Assuming $db is your PDO database connection
$val = new FormValidator($db);

$val->addRule('username', 'Username', 'required|min_len[5]|max_len[20]|is_unique[users,username]');
$val->addRule('email', 'Email', 'required|valid_email');
$val->addRule('password', 'Password', 'required|min_len[8]');
$val->addRule('confirm_password', 'Confirm Password', 'required|matches[password]');

if ($val->exec()) {
    $errors = $val->getErrors();
    // Handle validation errors
    print_r($errors);
} else {
    // Validation successful
    // Process form data
}
?>
```

### Multi-Language Support
```php
<?php

require_once 'form-validator.php';

// Assuming you have a database connection $db
$val = new FormValidation($db, 'tr'); // Set language to Turkish

// ... validation rules ...

if ($val->exec()) {
    $errors = $val->getErrors();
    // Handle validation errors (in Turkish)
    print_r($errors);
} else {
    // Validation successful
    // Process form data
}
?>
```

### Custom Helper Function
```php
<?php

require_once 'form-validator.php';

function sanitizeInput($value) {
    return htmlspecialchars(trim($value));
}

// Assuming you have a database connection $db
$val = new FormValidation($db);
$val->helperFunction = 'sanitizeInput';

$val->addRule('username', 'Username', 'required|min_len[5]|max_len[20]');

// ...
?>
```

### Available Validation Rules
`
- `required`: Field is required.
- `matches[field]`: Field must match another field.
- `is_unique[table,field]`: Field must be unique in the database.
- `min_len[n]`: Minimum length of the field.
- `max_len[n]`: Maximum length of the field.
- `exact_len[n]`: Exact length of the field.
- `range_len[n,m]`: Length of the field must be between n and m.
- `greater_than[n]`: Value must be greater than n.
- `less_than[n]`: Value must be less than n.
- `range[n,m]`: Value must be between n and m.
- `date_greater[date]`: Date must be greater than the given date.
- `date_less[date]`: Date must be less than the given date.
- `date_range[date1,date2]`: Date must be between date1 and date2.
- `age_greater[n]`: Age must be greater than n.
- `age_less[n]`: Age must be less than n.
- `age_range[n,m]`: Age must be between n and m.
- `char`: Field must be a single character.
- `alpha[options]`: Field must contain only alphabetic characters. Options: `u`, `l`, `n`, `s`, `_`, `.`.
- `hex`: Field must be a hexadecimal value.
- `num`, `+num`, `-num`: Field must be a number (positive or negative).
- `int`, `+int`, `-int`: Field must be an integer (positive or negative).
- `dec`, `+dec`, `-dec`: Field must be a decimal number (positive or negative).
- `valid_email`: Field must be a valid email address.
- `valid_emails`: Field must be a comma-separated list of valid email addresses.
- `valid_ip`: Field must be a valid IP address.
- `valid_ip_port`: Field must be a valid IP address and port.
- `valid_port`: Field must be a valid port number.
- `valid_url`: Field must be a valid URL.
- `valid_tel`: Field must be a valid phone number.
- `valid_date`: Field must be a valid date.
- `valid_datetime`: Field must be a valid date and time.
- `valid_hexcolor`: Field must be a valid hexadecimal color code.
- `valid_id[table,field]`: Field must be a valid ID in the database table.
- `valid_data[table,field]`: Field must be a valid data in the database table.
- `regex[regex]`: Field must match the given regular expression.

## License
This W-PHP Form Validator class is open-source software licensed under the [MIT license](https://mit-license.org/).
```
MIT License

Copyright (c) 2015 Ali Candan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contributing
Contributions are welcome! If you find any bugs or have suggestions for improvements, please `feel free to open an issue or submit a pull request on the GitHub repository.`

## Support
For any questions or support regarding the W-PHP Form Validator, you can refer to the project's GitHub repository or contact the author.
