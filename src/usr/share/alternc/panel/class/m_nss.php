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
    protected $group = array();
    protected $passwd = array();
    protected $shadow = array();

    protected $dir_backup = "/var/lib/alternc/backups/";
    protected $dir_extrausers = "/var/lib/extrausers/";

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

        // Persistent variable created and initialized with
        // object creation.
        static $is_this_a_rollback = false;

        if ($name === $this->field_name)
        {
            // The prefix was changed

            // Was the prefix changed during a rollback?
            if ($is_this_a_rollback)
            {
                // Yes, so we don't need to change it again.
                $is_this_a_rollback = false;
                return;
            }

            // Does the new prefix has a correct length?
            // Does the new prefix uses correct characters?
            if (!preg_match("#^[a-z0-9_]*$#", $new) || strlen($new)>14)
            {
                $msg->raise("ERROR", "nss", _("Prefix can only contains characters a-z, 0-9 and underscore and use at most 14 chars"));

                // Rollback the change, this will recall the hook
                $is_this_a_rollback = true;
                variable_set($name, $old);
                return;
            }

            $t = time();
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
        while ($db->next_record()) {
            $prefixed_login = $this->prefix . $db->f('login');
            $lines[] = $prefixed_login.":x:".$db->f('uid').":";
        }

        $this->group = $lines;
    }

    protected function define_passwd_file()
    {
        global $db;
        $db->query("SELECT login,uid FROM `membres`");
        $lines=array();
        while ($db->next_record()) {
            $prefixed_login = $this->prefix . $db->f('login');
            $lines[] = $prefixed_login.":x:".$db->f('uid').":".$db->f('uid')."::".getuserpath($db->f('login')).":/bin/false";
        }

        $this->passwd = $lines;
    }

    protected function define_shadow_file()
    {
        global $db;
        $db->query("SELECT login FROM `membres`");
        $lines=array();
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

        $this->shadow = $lines;
    }

    protected function write_content($file, $file_bck, $content_new)
    {
        $content_lines = false;
        if (file_exists($file)) {
            $content_lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        }

        if (!$content_lines) {
            $content_lines = [];
        }
        if (file_exists($file_bck)) {
            $content_lines_bck = file($file_bck, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $content_lines = array_diff($content_lines, $content_lines_bck);
        }
        $content_lines = array_merge($content_lines, $content_new);
        $content = implode("\n", $content_lines);
        $content_bck = implode("\n", $content_new);

        //Provide a final return carrier
        $content .= "\n";

        return $this->write_file($file_bck, $content_bck) && $this->write_file($file, $content);
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
        $file = $this->dir_extrausers . "group";
        $file_bck = $this->dir_backup . "group";

        return $this->write_content($file, $file_bck, $this->group);
    }

    protected function update_passwd_file()
    {
        $file = $this->dir_extrausers . "passwd";
        $file_bck = $this->dir_backup . "passwd";

        return $this->write_content($file, $file_bck, $this->passwd);

    }

    protected function update_shadow_file()
    {
        $file = $this->dir_extrausers . "shadow";
        $file_bck = $this->dir_backup . "shadow";
 
        return $this->write_content($file, $file_bck, $this->shadow);
    }

    protected function write_file($file, $content, $separator = "\n")
    {
        if (is_array($content)) {
            $content = implode($separator, $content);
        }
        return file_put_contents($file, $content, LOCK_EX);
    }

    public function hook_before_alternc_add_member($login)
    {
        global $msg;
        if($this->local_user_exists($login)) {
            $msg->log("nss", "hook_alternc_add_nember - ERROR: Aborting user creation");
            return _("A user with the same name already exists in the system");
        }
    }

}
