<?php

/**
 * Manage alternc account with nss service
 *
 * The function update_files() is never called by the
 * hooks because they don't have the proper rights to
 * modify the files. The files are written every 5 mins
 * by the PHP-FPM cron job, which execute the install.d
 * alternc-nss script, which call update_files() with
 * the proper rights.
 */
class m_nss
{
    protected $group_file;
    protected $passwd_file;
    protected $shadow_file;

    /** The name of the field in the table "variable"  */
    protected $field_name = "user_prefix";
    protected $prefix;

    function __construct()
    {
        $this->prefix = variable_get($this->field_name);
    }

    /** Hook function called after a value in the variable
     * table is modified through the admin control panel.
     *
     * @param $name the field changed in the variable table
     * @param $old the previous value overwritten in the table
     * @param $new the new value now in the table
     *
     * @return void
     */
    public function hook_variable_set($name, $old, $new)
    {
       global $msg;
        $msg->log("nss", "hook_variable_set($name,$old,$new)");

        if ($name === $this->field_name)
        {
            // The prefix was changed
            // Does the new prefix has a correct length?
            if (strlen($new)>14)
            {
                // User and group names are capped at 32 chars.
                // AlternC currently limit logins to 14 chars.
                // Prefix is limited to 14 to leave some margin.
                $msg->raise("ERROR", "nss", "The prefix is too long (14 chars max)");

                // Rollback the change, this will recall the hook
                variable_set($name, $old);
                return;
            }

            // Does the new prefix uses correct characters?
            if (!preg_match("#^[a-z0-9_]*$#", $new))
            {
                $msg->raise("ERROR", "nss", "Prefix can only contains characters a-z, 0-9 and underscore");

                // Rollback the change, this will recall the hook
                variable_set($name, $old);
                return;
            }

            $msg->raise("INFO", "nss", _("The modifications will take effect at %s.  Server time is %s."), array(date('H:i:s', ($t-($t%300)+300)), date('H:i:s', $t)));
        }
    }

    protected function local_user_exists($login)
    {
        global $msg;

        $prefixed_login = $this->prefix . $login;

        $user_exists = exec("getent passwd $prefixed_login 2>&1");
        $group_exists = exec("getent group $prefixed_login 2>&1");

        $msg->log("nss", "user_exists contains $user_exists", "group_exists contains $group_exists");

        if(!empty($user_exists) || !empty($group_exists))
        {
                $msg->raise("ERROR", "nss", "A user $prefixed_login exists on the system");
                return true;
        }

        return false;
    }

    public function define_files()
    {
        $this->define_group_file();
        $this->define_passwd_file();
        $this->define_shadow_file();
    }

    protected function define_group_file()
    {
        global $db;
        $db->query("SELECT login,uid FROM `membres`");
        $lines=array();
        $lines[]='##ALTERNC ACCOUNTS START##';
        while ($db->next_record()) {
            $prefixed_login = $this->prefix . $db->f('login');
            $lines[] = $prefixed_login.":x:".$db->f('uid').":";
        }
        $lines[]='##ALTERNC ACCOUNTS END##';

        $this->group_file = implode("\n", $lines);
    }

    protected function define_passwd_file()
    {
        global $db;
        $db->query("SELECT login,uid FROM `membres`");
        $lines=array();
        $lines[]='##ALTERNC ACCOUNTS START##';
        while ($db->next_record()) {
            $prefixed_login = $this->prefix . $db->f('login');
            $lines[] = $prefixed_login.":x:".$db->f('uid').":".$db->f('uid')."::".getuserpath($db->f('login')).":/bin/false";
        }
        $lines[]='##ALTERNC ACCOUNTS END##';

        $this->passwd_file = implode("\n", $lines);
    }

    protected function define_shadow_file()
    {
        global $db;
        $db->query("SELECT login FROM `membres`");
        $lines=array();
        $lines[]='##ALTERNC ACCOUNTS START##';
        while ($db->next_record()) {
            // shadow fields (9) :
            // 1. login
            // 2. encrypted password or * to prevent login
            // 3. date of last password change or '' meaning that password aging features are disabled
            // 4. minimum password age or '' or 0 meaning no minimum age
            // 5. maximum password age or '' meaning no maximum password age, no password warning period, and no password inactivity period
            // 6. password warning period or '' or 0 meaning there are no password warning period
            // 7. password inactivity period or '' for no enforcement
            // 8. account expiration date or '' for no expiration
            // 9. reserved
            $prefixed_login = $this->prefix . $db->f('login');
            $fields = array($prefixed_login, '*', '', '', '', '', '', '', '');
            $lines[] = implode(':', $fields);
        }
        $lines[]='##ALTERNC ACCOUNTS END##';

        $this->shadow_file = implode("\n", $lines);
    }

    public function update_files()
    {
        $this->define_files();
        $this->update_group_file();
        $this->update_passwd_file();
        $this->update_shadow_file();
    }

    protected function update_group_file()
    {
        $file = "/var/lib/extrausers/group";
        $content = file_get_contents($file);
        $content = preg_replace('/##ALTERNC ACCOUNTS START##.*##ALTERNC ACCOUNTS END##/ms', $this->group_file, $content, -1, $count);
        if ($count == 0) {
            $content .= $this->group_file;
        }
        return file_put_contents($file, $content, LOCK_EX);
    }

    protected function update_passwd_file()
    {
        $file = "/var/lib/extrausers/passwd";
        $content = file_get_contents($file);
        $content = preg_replace('/##ALTERNC ACCOUNTS START##.*##ALTERNC ACCOUNTS END##/ms', $this->passwd_file, $content, -1, $count);
        if ($count == 0) {
            $content .= $this->passwd_file;
        }

        return file_put_contents($file, $content, LOCK_EX);
    }

    protected function update_shadow_file()
    {
        $file = "/var/lib/extrausers/shadow";
        $content = file_get_contents($file);
        $content = preg_replace('/##ALTERNC ACCOUNTS START##.*##ALTERNC ACCOUNTS END##/ms', $this->shadow_file, $content, -1, $count);
        if ($count == 0) {
            $content .= $this->shadow_file;
        }

        return file_put_contents($file, $content, LOCK_EX);
    }

    public function hook_before_alternc_add_member($login)
    {
        global $msg;
        if($this->local_user_exists($login)) {
            $msg->log("nss", "hook_alternc_add_nember - ERROR: Aborting user creation");
            return false;
        }

        return true;
    }

}
