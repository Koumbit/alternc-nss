<?php

/**
 * Manage alternc account with nss service
 */
class m_nss
{
    protected $group_file;
    protected $passwd_file;

    public function define_files()
    {
        $this->define_group_file();
        $this->define_passwd_file();
    }

    protected function define_group_file()
    {
        global $db;
        $db->query("SELECT login,uid FROM `membres`");
        $lines=array();
        while ($db->next_record()) {
            $lines[] = $db->f('login').":x:".$db->f('uid').":";
        }

        $this->group_file = implode("\n", $lines);
    }

    protected function define_passwd_file()
    {
        global $db;
        $db->query("SELECT login,uid FROM `membres`");
        $lines=array();
        while ($db->next_record()) {
            $lines[] = $db->f('login').":x:".$db->f('uid').":".$db->f('uid').":::/bin/false";
        }

        $this->passwd_file = implode("\n", $lines);
    }
}
