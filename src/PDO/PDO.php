<?php

namespace KaalDB\PDO;

use PDO as PDOBase;

class PDO extends PDOBase
{
    private static array $instance = [];
    private int $transactionCounter = 0;

    public static function getInstance($dsn, $username = null, $passwd = null, $options = null): PDO
    {
        if (!isset(self::$instance[$dsn])) {
            self::$instance[$dsn] = new PDO($dsn, $username, $passwd, $options);
        }
        return self::$instance[$dsn];
    }

    public function __construct($dsn, $username = null, $passwd = null, $options = null)
    {
        parent::__construct($dsn, $username, $passwd, $options);
        $this->setAttribute(PDOBase::ATTR_ERRMODE, PDOBase::ERRMODE_EXCEPTION);
        self::$instance[$dsn] = $this;
    }

    public function beginTransaction(): bool
    {
        if (!$this->transactionCounter++) {
            return parent::beginTransaction();
        }
        $this->exec('SAVEPOINT trans' . $this->transactionCounter);
        return $this->transactionCounter >= 0;    
    }

    public function commit(): bool
    {
        $this->transactionCounter--;
        if ($this->transactionCounter === 0) {
            parent::commit();
        }
        return $this->transactionCounter >= 0;
    }

    public function rollBack(): bool
    {
        if (--$this->transactionCounter) {
            $this->exec('ROLLBACK TO trans' . $this->transactionCounter + 1);
            return true;
        }
        return parent::rollBack();
    }

    public function cancelTransaction(): void
    {
        $this->transactionCounter = 0;
        $this->rollBack();
    }

    public function completeTransaction(): void
    {
        $this->transactionCounter = 0;
        $this->commit();
    }

    public function inTransaction(): bool
    {
        return $this->transactionCounter > 0;
    }
}