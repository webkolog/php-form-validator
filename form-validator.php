<?php
/*
W-PHP Form Validator
=====================
File: form-validator.php
Author: Ali Candan [Webkolog] <webkolog@gmail.com> 
Homepage: http://webkolog.net
GitHub Repo: https://github.com/webkolog/php-form-validator
Last Modified: 2015-07-27
Created Date: 2015-07-27
Compatibility: PHP 5.4+
@version     1.2

Copyright (C) 2015 Ali Candan
Licensed under the MIT license http://mit-license.org

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

<?php

class FormValidator {
    private $allowLowerMLC = 'ğüşıöç';
    private $allowUpperMLC = 'ĞÜŞİÖÇ';
    private $allowMLC = 'ĞÜŞİÖÇğüşıöç';
    private $error = false;
    private $validList = array();
    private $errorMessages = array();
    private $singleErrors = array();
    public $helperFunction = null;
    public $postMethod = 'post';
    private $db;
    private $language = 'en';
    private $langData = [];

    public function __construct($db, $language = 'en') {
        $this->db = $db;
        $this->setLanguage($language);
    }

    public function setLanguage($language) {
        $this->language = $language;
        $langFile = __DIR__ . '/languages/' . $language . '.php';
        if (file_exists($langFile)) {
            $this->langData = include $langFile;
        } else {
            $this->langData = include __DIR__ . '/languages/en.php';
        }
    }

    private function getLang($key, $replacements = []) {
        $message = isset($this->langData[$key]) ? $this->langData[$key] : $key;
        foreach ($replacements as $placeholder => $value) {
            $message = str_replace(':' . $placeholder, $value, $message);
        }
        return $message;
    }

    public function exec() {
        foreach ($this->validList as $validItem)
            $this->execValid($validItem);
        return $this->checkError();
    }

    public function checkValid($value, $label, $valid) {
        $this->singleErrors = array();
        $validItem = array("name" => null, "label" => $label, "valid" => $valid, "method" => null, "value" => $value, "multiple" => false);
        $this->execValid($validItem);
        return $this->singleErrors;
    }
    
    public function addRule($name, $label, $valid, $method = null) {
        $validItem = array("name" => $name, "label" => $label, "valid" => $valid, "method" => $method, "value" => null, "multiple" => true);
        array_push($this->validList, $validItem);
    }
    
    public function addRuleVal($value, $label, $valid) {
        $validItem = array("name" => null, "label" => $label, "valid" => $valid, "method" => null, "value" => $value, "multiple" => true);
        array_push($this->validList, $validItem);
    }
    
    public function addErrorMessage($message) {
        array_push($this->errorMessages, $message);
    }
    
    public function addErrorMessages($messages) {
        if ($this->countErrors() > 0)
            array_merge($this->errorMessages, $messages);
        else
            $this->errorMessages = $messages;
    }
    
    public function countErrors() {
        return count($this->errorMessages);
    }
    
    public function getErrors() {
        return $this->errorMessages;
    }
    
    public function checkError() {
        return $this->countErrors() > 0;
    }
    
    public function render() {
        /*
        Here you can create an algorithm that will return the codes
        */
    }
    
    private function getPost($name, $method = null) {
        $method = ($method == null ? $this->postMethod : $method);
        $value = ($method == 'get' ? $_GET[$name] : $_POST[$name]);
        $checkFunc = false;
        if ($this->helperFunction != null) {
            if (function_exists($this->helperFunction))
                $checkFunc = true;
        }
        return ($checkFunc ? call_user_func($this->helperFunction, $value) : $value);
    }
    
    private function execValid($validItem) {
        $name = $validItem["name"];
        $label = $validItem["label"];
        $valid = $validItem["valid"];
        $method = $validItem["method"];
        $value = $validItem["value"];
        $multiple = $validItem["multiple"];
        if ($name != null) {
            $value = $this->getPost($name, $method);
            $named = true;
        } else {
            $named = false;
        }
        $valid = preg_replace('@(?!\[[a-z]*\])\|(?![a-z]*\])@', '{|}', $valid);
        $valids = explode("{|}", $valid);
        foreach ($valids as $validItem) {
            $this->parseValid($named, $name, $label, $validItem, $value, $method, $multiple);
        }
    }
    
    private function parseValid($named, $name, $label, $valid, $value, $method, $multiple) {
        $value = ($named == true ? $this->getPost($name, $method) : $value);
        $date_pattern = "(([1-9]{1}[0-9]{3})-(0[1-9]{1}|1[0-2]{1})-(0[1-9]{1}|[1-2]{1}[0-9]{1}|3[0-1]{1})( ([0-1]{1}[0-9]{1}|2[0-3]{1}):([0-5]{1}[0-9]{1}):?([0-5]{1}[0-9]{1})*)*)";
        if ($valid == "required") {
            if ($value != 0 || $value != "0" || $value != false) {
                if (!isset($value) || is_null($value) || empty($value))
                    $this->addErrorMessage($this->getLang('required', ['label' => $label]));
            }
        } else {
            if (strlen($value) > 0) {
                if (preg_match("@^matches\[(.*)\]@", $valid, $matches)) {
                    $name2 = $matches[1];
                    $value2 = ($named == true ? $this->getPost($name2, $method) : $name2);
                    if ($value != $value2) {
                        if ($named == true) {
                            if (function_exists('array_column')) {
                                $key = array_search($name2, array_column($this->validList, "name"));
                            } else {
                                $i = 0;
                                foreach ($this->validList as $validItem) {
                                    if ($validItem["name"] == $name2) {
                                        $key = $i;
                                        break;
                                    }
                                    $i++;
                                }
                            }
                            if (isset($key)) {
                                $label2 = $this->validList[$key]["label"];
                                $this->addErrorMessage($this->getLang('matches', ['label' => $label, 'label2' => $label2]));
                            } else {
                                $this->addErrorMessage($this->getLang('matches', ['label' => $label, 'label2' => 'some other field']));
                            }
                        }
                    }
                } else if (preg_match("@^is_unique\[([A-z0-9_-]+),([A-z0-9_-]+)\]$@", $valid, $matches)) {
                    $tableName = $matches[1];
                    $fieldName = $matches[2];
                    $result = $this->db->prepare("SELECT * FROM $tableName WHERE $fieldName = ? ");
                    $result->execute(array($value));
                    $count = $result->rowCount();
                    if ($count > 0)
                        $this->addErrorMessage($this->getLang('is_unique', ['label' => $label]));
                } else if (preg_match("@^min_len\[([0-9]+)\]@", $valid, $matches)) {
                    $min_len = $matches[1];
                    if (strlen(htmlspecialchars_decode($value)) < $min_len)
                        $this->addErrorMessage($this->getLang('min_len', ['label' => $label, 'min_len' => $min_len]));
                } else if (preg_match("@^max_len\[([0-9]+)\]@", $valid, $matches)) {
                    $max_len = $matches[1];
                    if (strlen(htmlspecialchars_decode($value)) > $max_len)
                        $this->addErrorMessage($this->getLang('max_len', ['label' => $label, 'max_len' => $max_len]));
                } else if (preg_match("@^exact_len\[([0-9]+)\]@", $valid, $matches)) {
                    $exact_len = $matches[1];
                    if (strlen(htmlspecialchars_decode($value)) != $exact_len)
                        $this->addErrorMessage($this->getLang('exact_len', ['label' => $label, 'exact_len' => $exact_len]));
                } else if (preg_match("@^range_len\[([0-9]+),([0-9]+)\]@", $valid, $matches)) {
                    $min_len = $matches[1];
                    $max_len = $matches[2];
                    $count = strlen(htmlspecialchars_decode($value));
                    if ($count < $min_len || $count > $max_len)
                        $this->addErrorMessage($this->getLang('range_len', ['label' => $label, 'min_len' => $min_len, 'max_len' => $max_len]));
                } else if (preg_match("@^greater_than\[([0-9]+)\]@", $valid, $matches)) {
                    $max = intval($matches[1]);
                    if ($value <= $max)
                        $this->addErrorMessage($this->getLang('greater_than', ['label' => $label, 'min_len' => ($max + 1)]));
                } else if (preg_match("@^less_than\[([0-9]+)\]@", $valid, $matches)) {
                    $min = $matches[1];
                    if ($value >= $min)
                        $this->addErrorMessage($this->getLang('less_than', ['label' => $label, 'max_len' => ($min - 1)]));
                } else if (preg_match("@^range\[([0-9]+),([0-9]+)\]@", $valid, $matches)) {
                    $min = $matches[1];
                    $max = $matches[2];
                    if ($value < $min || $value > $max)
                        $this->addErrorMessage($this->getLang('range', ['label' => $label, 'min' => $min, 'max' => $max]));
                } else if (preg_match("@^date_range\[" . $date_pattern . "," . $date_pattern . "\]@", $valid, $matches)) {
                    $min = $matches[1];
                    $max = $matches[9];
                    if ($value < $min || $value > $max)
                        $this->addErrorMessage($this->getLang('date_range', ['label' => $label, 'min' => $min, 'max' => $max]));
                } else if (preg_match("@^date_less\[" . $date_pattern . "\]@", $valid, $matches)) {
                    $max = $matches[1];
                    if ($value >= $max)
                        $this->addErrorMessage($this->getLang('date_less', ['label' => $label, 'max' => $max]));
                } else if (preg_match("@^date_greater\[" . $date_pattern . "\]@", $valid, $matches)) {
                    $min = $matches[1];
                    if ($value <= $min)
                        $this->addErrorMessage($this->getLang('date_greater', ['label' => $label, 'min' => $min]));
                } else if (preg_match("@^age_range\[([0-9]+),([0-9]+)\]@", $valid, $matches)) {
                    $min = $matches[1];
                    $max = $matches[2];
                    list($bY, $bM, $bD) = explode("-", $value);
                    list($y, $m, $d) = explode("-", date("Y-m-d"));
                    $age = ($y - $bY) - ($m < $bM || ($m == $bM && $d < $bD) ? 1 : 0);
                    if ($age < $min || $age > $max)
                        $this->addErrorMessage($this->getLang('age_range', ['label' => $label, 'min' => $min, 'max' => $max]));
                } else if (preg_match("@^age_greater\[([0-9]+)\]@", $valid, $matches)) {
                    $max = $matches[1];
                    list($bY, $bM, $bD) = explode("-", $value);
                    list($y, $m, $d) = explode("-", date("Y-m-d"));
                    $age = ($y - $bY) - ($m < $bM || ($m == $bM && $d < $bD) ? 1 : 0);
                    if ($age <= $max)
                        $this->addErrorMessage($this->getLang('age_greater', ['label' => $label, 'min' => ($max + 1)]));
                } else if (preg_match("@^age_less\[([0-9]+)\]@", $valid, $matches)) {
                    $min = $matches[1];
                    list($bY, $bM, $bD) = explode("-", $value);
                    list($y, $m, $d) = explode("-", date("Y-m-d"));
                    $age = ($y - $bY) - ($m < $bM || ($m == $bM && $d < $bD) ? 1 : 0);
                    if ($age >= $min)
                        $this->addErrorMessage($this->getLang('age_less', ['label' => $label, 'max' => ($min - 1)]));
                } else if ($valid == "char") {
                    if (!preg_match("@^([A-z]?)$@", $value))
                        $this->addErrorMessage($this->getLang('char', ['label' => $label]));
                } else if (preg_match("@^alpha(\[([ulns\_\.]+)\])?$@", $valid, $matches)) {
                    $signs = $matches[2];
                    $ignore_cs = false;
                    $pattern = "";
                    $sign_count = strlen($signs);
                    $allowing_things = array();
                    for ($i = 0; $i < $sign_count; $i++) {
                        $sign = $signs{$i};
                        if ($sign == '_') {
                            $pattern.="\_";
                            array_push($allowing_things, "alt çizgi");
                        } else if ($sign == '.') {
                            $pattern.="\.";
                            array_push($allowing_things, "nokta");
                        } else if ($sign == 'n') {
                            $pattern.="0-9";
                            array_push($allowing_things, "rakam");
                        } else if ($sign == 's') {
                            $pattern.="\s";
                            array_push($allowing_things, "boşluk");
                        } else if ($sign == '') {
                            $pattern.="A-Z" . $this->allowUpperMLC;
                            $ignore_cs = true;
                            array_push($allowing_things, "büyük harf");
                        } else if ($sign == 'l') {
                            $pattern.="a-z" . $this->allowLowerMLC;
                            $ignore_cs = true;
                            array_push($allowing_things, "küçük harf");
                        }
                    }
                    if (!$ignore_cs) {
                        $pattern .="A-Za-z" . $this->allowMLC;
                        array_push($allowing_things, "harf");
                    }
                    $pattern = "@^([" . $pattern . "]*)$@";
                    $allowing_text = join(", ", $allowing_things);
                    $allowing_text = preg_replace("@, ([A-Za-z" . $this->allowMLC . "0-9\s]+)$@", " ve $1", $allowing_text);
                    $errorMessage = $this->getLang('alpha', ['label' => $label, 'allowing_text' => $allowing_text]);
                    if (!preg_match($pattern, $value))
                        $this->addErrorMessage($errorMessage);
                } else if ($valid == "hex") {
                    if (!preg_match("@^[0-9abcdefABCDEF]+$@", $value))
                        $this->addErrorMessage($this->getLang('hex', ['label' => $label]));
                } else if (preg_match("@^([\+\-])?(num)$@", $valid, $matches)) {
                    if (is_numeric($value)) {
                        $sign = $matches[0];
                        if ($sign == "+num") {
                            if ($value < 1)
                                $this->addErrorMessage($this->getLang('num', ['label' => $label]));
                        } else if ($sign == "-num") {
                            if ($value > -1)
                                $this->addErrorMessage($this->getLang('num', ['label' => $label]));
                        }
                    } else {
                        $this->addErrorMessage($this->getLang('num', ['label' => $label]));
                    }
                } else if (preg_match("@^([\+\-])?(int)$@", $valid, $matches)) {
                    if (preg_match("@^[\-]?[0-9]+$@", $value)) {
                        $sign = $matches[0];
                        if ($sign == "+int") {
                            if ($value < 1)
                                $this->addErrorMessage($this->getLang('int', ['label' => $label]));
                        } else if ($sign == "-int") {
                            if ($value > -1)
                                $this->addErrorMessage($this->getLang('int', ['label' => $label]));
                        }
                    } else {
                        $this->addErrorMessage($this->getLang('int', ['label' => $label]));
                    }
                } else if (preg_match("@^([\+\-])?(dec|flo|dou)$@", $valid, $matches)) {
                    if (preg_match("@^[\-]?[0-9]+\.[0-9]+$@", $value)) {
                        $sign = $matches[0];
                        if ($sign == "+dec" || $sign == "+flo" || $sign == "+dou") {
                            if ($value < 1)
                                $this->addErrorMessage($this->getLang('dec', ['label' => $label]));
                        } else if ($sign == "-dec" || $sign == "-flo" || $sign == "-dou") {
                            if ($value > -1)
                                $this->addErrorMessage($this->getLang('dec', ['label' => $label]));
                        }
                    } else {
                        $this->addErrorMessage($this->getLang('dec', ['label' => $label]));
                    }
                } else if ($valid == "valid_email") {
                    if (!preg_match("@^([a-z0-9\_\.]+)\@([a-z0-9\-]+\.[a-z0-9\-\.]{2,})$@", $value))
                        $this->addErrorMessage($this->getLang('valid_email', ['label' => $label]));
                } else if ($valid == "valid_emails") {
                    if (
                            !preg_match("@^([a-z0-9\_\.]+)\@([a-z0-9\-]+\.[a-z0-9\-\.]{2,})$@", $value) &&
                            (
                            !preg_match("@^((\s*)[a-z0-9\_\.]+)\@([a-z0-9\-]+\.[a-z0-9\-\.]{2,}(\s*);)@", $value) ||
                            !preg_match("@((\s*)[a-z0-9\_\.]+)\@([a-z0-9\-]+\.[a-z0-9\-\.]{2,}(\s*))$@", $value)
                            )
                    ) {
                        $this->addErrorMessage($this->getLang('valid_emails', ['label' => $label]));
                    }
                } else if ($valid == "valid_ip") {
                    if (!preg_match("@^(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))\.(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))\.(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))\.(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))$@", $value)) {
                        $this->addErrorMessage($this->getLang('valid_ip', ['label' => $label]));
                    }
                } else if ($valid == "valid_ip_port") {
                    if (!preg_match("@^(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))\.(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))\.(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))\.(1?[0-9]{1,2}|2(5[0-5]|[0-4][0-9]))\:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$@", $value))
                        $this->addErrorMessage($this->getLang('valid_ip_port', ['label' => $label]));
                } else if ($valid == "valid_port") {
                    if (!preg_match("@^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$@", $value))
                        $this->addErrorMessage($this->getLang('valid_port', ['label' => $label]));
                } else if ($valid == "valid_url") {
                    if (!preg_match("@^(http\:\/\/|https\:\/\/)?(www\.)?([a-z0-9\-]+\.[a-z0-9\-\.]{2,})$@", $value))
                        $this->addErrorMessage($this->getLang('valid_url', ['label' => $label]));
                } else if ($valid == "valid_tel") {
                    if (!preg_match("@^(\([1-9][0-9]{2}\) ([0-9]{3})-([0-9]{4}))$@", $value))
                        $this->addErrorMessage($this->getLang('valid_tel', ['label' => $label]));
                } else if ($valid == "valid_date") {
                    if (!preg_match("@^(([1-9]{1}[0-9]{3})-(0[1-9]{1}|1[0-2]{1})-(0[1-9]{1}|[1-2]{1}[0-9]{1}|3[0-1]{1}))$@", $value))
                        $this->addErrorMessage($this->getLang('valid_date', ['label' => $label]));
                } else if ($valid == "valid_datetime") {
                    if (!preg_match("@^(([1-9]{1}[0-9]{3})-(0[1-9]{1}|1[0-2]{1})-(0[1-9]{1}|[1-2]{1}[0-9]{1}|3[0-1]{1})( ([0-1]{1}[0-9]{1}|2[0-3]{1}):([0-5]{1}[0-9]{1}):?([0-5]{1}[0-9]{1})*)*)$@", $value))
                        $this->addErrorMessage($this->getLang('valid_datetime', ['label' => $label]));
                } else if ($valid == "valid_hexcolor") {
                    if (!preg_match("@^\#(([0-9abcdefABCDEF]{3}){1,2})$@", $value))
                        $this->addErrorMessage($this->getLang('valid_hexcolor', ['label' => $label]));
                } else if (preg_match("@^valid_id\[([A-z0-9_-]+),([A-z0-9_-]+)\]$@", $valid, $matches)) {
                    if (preg_match("@^[\-]?[0-9]+$@", $value) && $value > 0) {
                        $tableName = $matches[1];
                        $fieldName = $matches[2];
                        $result = $this->db->prepare("SELECT COUNT(*) FROM $tableName WHERE $fieldName = ? ");
                        $result->execute(array($value));
                        $count = $result->fetchColumn();
                        if ($count == 0)
                            $this->addErrorMessage($this->getLang('valid_id', ['label' => $label]));
                    } else {
                        $this->addErrorMessage($this->getLang('valid_id', ['label' => $label]));
                    }
                } else if (preg_match("@^valid_data\[([A-z0-9_-]+),([A-z0-9_-]+)\]$@", $valid, $matches)) {
                    if (strlen($value) > 0) {
                        $tableName = $matches[1];
                        $fieldName = $matches[2];
                        $result = $this->db->prepare("SELECT COUNT(*) FROM $tableName WHERE $fieldName = ? ");
                        $result->execute(array($value));
                        $count = $result->fetchColumn();
                        if ($count == 0)
                            $this->addErrorMessage($this->getLang('valid_data', ['label' => $label]));
                    }
                } else if (preg_match("@^regex\[(.+)\]$@", $valid, $matches)) {
                    $regex_pattern = $matches[1];
                    if (!preg_match($regex_pattern, $value))
                        $this->addErrorMessage($this->getLang('regex', ['label' => $label]));
                } else {
                    throw new Exception("Valid is not correct (Name: " . $name . ", Valid: " . $valid . ")");
                }
            }
        }
    }
}
