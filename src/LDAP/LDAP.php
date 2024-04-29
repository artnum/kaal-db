<?php

namespace KaalDB\LDAP;

use LDAP\Connection;
use Generator;
use Exception;
use stdClass;


/* from ldap.h */
const LDAP_SUCCESS =                        0x00;
const LDAP_OPERATIONS_ERROR =               0x01;
const LDAP_PROTOCOL_ERROR =                 0x02;
const LDAP_TIMELIMIT_EXCEEDED =             0x03;
const LDAP_SIZELIMIT_EXCEEDED =             0x04;
const LDAP_COMPARE_FALSE =                  0x05;
const LDAP_COMPARE_TRUE =                   0x06;
const LDAP_AUTH_METHOD_NOT_SUPPORTED =      0x07;
const LDAP_STRONG_AUTH_NOT_SUPPORTED =      LDAP_AUTH_METHOD_NOT_SUPPORTED;
const LDAP_STRONG_AUTH_REQUIRED =           0x08;
const LDAP_STRONGER_AUTH_REQUIRED =         LDAP_STRONG_AUTH_REQUIRED;
const LDAP_REFERRAL =                       0x0a;
const LDAP_ADMINLIMIT_EXCEEDED =            0x0b;
const LDAP_UNAVAILABLE_CRITICAL_EXTENSION = 0x0c;
const LDAP_CONFIDENTIALITY_REQUIRED =       0x0d;
const LDAP_SASL_BIND_IN_PROGRESS	=       0x0e;
const LDAP_NO_SUCH_ATTRIBUTE =              0x10;
const LDAP_UNDEFINED_TYPE =                 0x11;
const LDAP_INAPPROPRIATE_MATCHING =         0x12;
const LDAP_CONSTRAINT_VIOLATION =           0x13;
const LDAP_TYPE_OR_VALUE_EXISTS =           0x14;
const LDAP_INVALID_SYNTAX =                 0x15;
const LDAP_NO_SUCH_OBJECT =                 0x20;
const LDAP_ALIAS_PROBLEM =                  0x21;
const LDAP_INVALID_DN_SYNTAX =              0x22;
const LDAP_ALIAS_DEREF_PROBLEM =            0x24;
const LDAP_X_PROXY_AUTHZ_FAILURE =          0x2F;
const LDAP_INAPPROPRIATE_AUTH =             0x30;
const LDAP_INVALID_CREDENTIALS =            0x31;
const LDAP_INSUFFICIENT_ACCESS =            0x32;
const LDAP_BUSY =                           0x33;
const LDAP_UNAVAILABLE =                    0x34;
const LDAP_UNWILLING_TO_PERFORM =           0x35;
const LDAP_LOOP_DETECT =                    0x36;
const LDAP_NAMING_VIOLATION =               0x40;
const LDAP_OBJECT_CLASS_VIOLATION =         0x41;
const LDAP_NOT_ALLOWED_ON_NONLEAF =         0x42;
const LDAP_NOT_ALLOWED_ON_RDN =             0x43;
const LDAP_ALREADY_EXISTS =                 0x44;
const LDAP_NO_OBJECT_CLASS_MODS =           0x45;
const LDAP_AFFECTS_MULTIPLE_DSAS =          0x47;
const LDAP_VLV_ERROR =                      0x4C;
const LDAP_OTHER =                          0x50;

/* From 0x7000 and above is for private application use */
const LDAP_OPT_PRIVATE_EXTENSION_BASE =     0x7000;
const LDAP_OPT_KAALDB_MAX_BUSY_TRIES =      0x7001;
const LDAP_OPT_KAALDB_BUSY_WAIT_TIME =      0x7002;
const LDAP_OPT_KAALDB_AUTH_USER =           0x7003;
const LDAP_OPT_KAALDB_AUTH_PASSWORD =       0x7004;

class LDAP {
    private static array $instance = [];
    private Connection $connection;
    private int $maxBusyTries = 10;
    private int $busyWaitTime = 1000;

    public function __construct(string $uri, array $options = [])
    {
        $auth = ['dn' => '', 'password' => ''];
        $this->connection = ldap_connect($uri);
        if ($this->connection === false) {
            throw new Exception("Could not connect to LDAP server: $uri");
        }
        ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);
        foreach ($options as $option => $value) {
            if ($option >= LDAP_OPT_PRIVATE_EXTENSION_BASE) {
                switch($option) {
                    case LDAP_OPT_KAALDB_MAX_BUSY_TRIES:
                        $this->maxBusyTries = intval($value);
                        if ($this->maxBusyTries <= 0) {
                            $this->maxBusyTries = 0;
                        }
                        break;
                    case LDAP_OPT_KAALDB_BUSY_WAIT_TIME:
                        $this->busyWaitTime = intval($value);
                        if ($this->busyWaitTime <= 0) {
                            $this->busyWaitTime = 1000;
                        }
                        break;
                    case LDAP_OPT_KAALDB_AUTH_USER:
                        $auth['dn'] = $value;
                        break;
                    case LDAP_OPT_KAALDB_AUTH_PASSWORD:
                        $auth['password'] = $value;
                        break;
                }
                continue;
            }
            ldap_set_option($this->connection, $option, $value);
        }

        if (!ldap_bind($this->connection, $auth['dn'], $auth['password'])) {
            throw new Exception("Could not bind to LDAP server: $uri");
        }
        self::$instance[$uri] = $this;
    }

    function __destruct()
    {
        ldap_unbind($this->connection);
    }

    public static function getInstance(string $uri, $options = []): LDAP
    {
        if (!isset(self::$instance[$uri])) {
            self::$instance[$uri] = new LDAP($uri, $options);
        }
        return self::$instance[$uri];
    }

    function getConnection (): Connection {
        return $this->connection;
    }

    public function search(string $baseDn, string $filter, array $attributes = ['*']): Generator
    {
        $tries = $this->maxBusyTries;
        do {
            $result = ldap_search(
                $this->connection,
                $baseDn,
                $filter,
                $attributes
            );

            if ($result === false) {
                throw new Exception("Could not search LDAP server: $baseDn");
            }

            if (ldap_parse_result($this->connection, $result, $errcode, $matcheddn, $errmsg, $referrals, $serverctrls)) {
                if ($errcode !== LDAP_SUCCESS) {
                    throw new Exception("Could not search LDAP server: $baseDn ($errcode) $errmsg");
                }
            }

            if ($result === false) {
                throw new Exception("Could not search LDAP server: $baseDn");
            }

            if ($errcode === LDAP_BUSY) {
                if (--$tries <= 0) {
                    throw new Exception("Could not search LDAP server: $baseDn (LDAP_BUSY)");
                }
                usleep($this->busyWaitTime);
                continue;
            }

            if ($errcode !== LDAP_SUCCESS) {
                throw new Exception("Could not search LDAP server: $baseDn ($errcode) $errmsg");
            }

            for(
                    $entry = ldap_first_entry($this->connection, $result);
                    $entry !== false; 
                    $entry = ldap_next_entry($this->connection, $entry)
                ) {
                yield Entry::fromResultEntry($this->connection, $entry);
            }
        } while ($errcode !== LDAP_SUCCESS);
    }

    public function list(string $baseDn, string $filter, array $attributes = ['*']): Generator
    {
        $tries = $this->maxBusyTries;
        do {
            $result = ldap_list(
                $this->connection,
                $baseDn,
                $filter,
                $attributes
            );
            if ($result === false) {
                throw new Exception("Could not search LDAP server: $baseDn");
            }
            if (!ldap_parse_result($this->connection, $result, $errcode, $matcheddn, $errmsg, $referrals, $serverctrls)) {
                throw new Exception("Could not search LDAP server: $baseDn ($errcode) $errmsg");
            }

            if ($errcode === LDAP_BUSY) {
                if (--$tries <= 0) {
                    throw new Exception("Could not search LDAP server: $baseDn (LDAP_BUSY)");
                }
                usleep($this->busyWaitTime);
                continue;
            }

            if ($errcode !== LDAP_SUCCESS) {
                throw new Exception("Could not search LDAP server: $baseDn ($errcode) $errmsg");
            }

            for(
                $entry = ldap_first_entry($this->connection, $result);
                $entry !== false; 
                $entry = ldap_next_entry($this->connection, $entry)
            ) {
                yield Entry::fromResultEntry($this->connection, $entry);
            }
        } while ($errcode !== LDAP_SUCCESS);
    }

    public function read(string $dn, array $attributes = ['*']): Entry
    {
        $tries = $this->maxBusyTries;
        do {
            $result = ldap_read($this->connection, $dn, "(objectclass=*)", $attributes);
            if ($result === false) {
                throw new Exception("Could not read LDAP server: $dn");
            }

            if (!ldap_parse_result($this->connection, $result, $errcode, $matcheddn, $errmsg, $referrals, $serverctrls)) {
                throw new Exception("Could not read LDAP server: $dn ($errcode) $errmsg");
            }

            if ($errcode === LDAP_BUSY) {
                if (--$tries <= 0) {
                    throw new Exception("Could not read LDAP server: $dn (LDAP_BUSY)");
                }
                usleep($this->busyWaitTime);
                continue;
            }

            if ($errcode !== LDAP_SUCCESS) {
                throw new Exception("Could not read LDAP server: $dn ($errcode) $errmsg");
            }

            $entry = ldap_first_entry($this->connection, $result);
            if ($entry === false) {
                throw new Exception("Could not find LDAP entry: $dn");
            }

            return Entry::fromResultEntry($this->connection, $entry);
        } while ($errcode !== LDAP_SUCCESS);
    }
    /**
     * Add LDAP entry. If entry already exists, modify it.
     * @param string $dn Entry to add
     * @param stdClass|array $entry Attributes values
     * @return Entry Created entry
     * @throws Exception 
     */
    public function add(string $dn, stdClass|array $entry): Entry
    {
        $tries = $this->maxBusyTries;
        if ($entry instanceof stdClass) {
            $entry = (array) $entry;
        }
        $original = null;
        try {
            $original = $this->read($dn);
        } catch (Exception $e) {
            // Ignore
        }
        if ($original !== null) {
            return $this->modify($dn, $entry, $original);
        }

        do {
            $result = ldap_add_ext(
                $this->connection,
                $dn,
                $entry,
                [
                    ['oid' => LDAP_CONTROL_POST_READ, 'value' => ['attrs' => ['*']], 'iscritical' => true]
                ]
            );

            if (!$result) {
                throw new Exception("Could not add LDAP entry: $dn");
            }

            if (!ldap_parse_result($this->connection, $result, $errcode, $matcheddn, $errmsg, $referrals, $serverctrls)) {
                throw new Exception("Could not parse LDAP result: $dn");
            }
            if ($errcode === LDAP_ALREADY_EXISTS) {
                return $this->modify($dn, $entry);
            }
            
            if ($errcode === LDAP_SUCCESS) {
                return Entry::fromArray($serverctrls[LDAP_CONTROL_POST_READ]['value']);
            }

            if ($errcode === LDAP_BUSY) {
                if (--$tries <= 0) {
                    throw new Exception("Could not add LDAP entry: $dn (LDAP_BUSY)");
                }
                usleep($this->busyWaitTime);
                continue;
            }
            throw new Exception("Could not add LDAP entry: $dn ($errcode) $errmsg");
        } while (1);

    }

    /**
     * Modify or add LDAP entry. Can replace, add or delete attributes. If modify fails, add the entry.
     * Return the modified entry.
     * @param string $dn Entry to modify
     * @param stdClass|array $entry Attributes values, starts with '-' or value set to null or [] to delete.
     * @return Entry Modified entry
     * @throws Exception 
     */
    public function modify(string $dn, stdClass|array $entry): Entry
    {
        if ($entry instanceof stdClass) {
            $entry = (array) $entry;
        }
        
        $mods = [];

        foreach ($entry as $attribute => $values) {
            $op = substr($attribute, 0, 1);
            if ($op === '-' || $op === '+') {
                $attribute = substr($attribute, 1);
            }
            /* delete attribute */
            if ($values === [] || $values === null || $op === '-') {
                $mods[$attribute] = [];
                continue;
            }
            if (!is_array($values)) {
                $values = [$values];
            }
            $mods[$attribute] = array_values($values);
        }
        $tries = $this->maxBusyTries;
        do {
            $result = ldap_mod_replace_ext(
                $this->connection,
                $dn,
                $mods,
                [
                    ['oid' => LDAP_CONTROL_POST_READ, 'value' => ['attrs' => ['*']], 'iscritical' => true]
                ]
            );
            if (!$result) {
                throw new Exception("Could not modify LDAP entry: $dn");
            }
            if (!ldap_parse_result($this->connection, $result, $errcode, $matcheddn, $errmsg, $referrals, $serverctrls)) {
                throw new Exception("Could not parse LDAP result: $dn");
            }
            
            if ($errcode === LDAP_SUCCESS) {
                return Entry::fromArray($serverctrls[LDAP_CONTROL_POST_READ]['value']);
            }

            if ($errcode === LDAP_NO_SUCH_OBJECT) {
                return $this->add($dn, $entry);
            }

            if ($errcode === LDAP_BUSY) {
                if (--$tries <= 0) {
                    throw new Exception("Could not modify LDAP entry: $dn (LDAP_BUSY)");
                }
                usleep($this->busyWaitTime);
                continue;
            }

            throw new Exception("Could not modify LDAP entry: $dn ($errcode) $errmsg");
        } while (1);
    }

    function delete (string $dn): void
    {
        $results = ldap_list($this->connection, $dn, "(objectclass=*)", ['dn']);
        if ($results === false) {
            if (!ldap_delete($this->connection, $dn)) {
                throw new Exception("Could not delete LDAP entry: $dn");
            }
        }
        for (
            $entry = ldap_first_entry($this->connection, $results);
            $entry !== false;
            $entry = ldap_next_entry($this->connection, $entry)
        ) {
            $dn = ldap_get_dn($this->connection, $entry);
            $this->delete($dn);
        }
        if (!ldap_delete($this->connection, $dn)) {
            throw new Exception("Could not delete LDAP entry: $dn");
        }
    }

    function move (string $dn, string $newParent): void
    {
        if (!ldap_rename($this->connection, $dn, "", $newParent, true)) {
            throw new Exception("Could not move LDAP entry: $dn");
        }
    }
}