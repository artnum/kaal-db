<?php

namespace KaalDB\LDAP;

use LDAP\{Connection, Result, ResultEntry};
use stdClass;
use Normalizer;

class Entry extends stdClass {

    static function fromResultEntry (Connection $connection, ResultEntry $result): Entry {
        $entry = new Entry();
        for (
            $attr = ldap_first_attribute($connection, $result);
            $attr !== false;
            $attr = ldap_next_attribute($connection, $result)
        ) {
            $values = ldap_get_values($connection, $result, $attr);
            unset($values['count']);
            $entry->$attr =  array_values($values);
        }
        $entry->dn = ldap_get_dn($connection, $result);   
        return $entry;    
    }

    static function fromArray (array $data): Entry {
        $entry = new Entry();
        foreach ($data as $key => $value) {
            $entry->$key = $value;
        }
        return $entry;
    }
}