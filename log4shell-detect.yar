rule log4shell {
   meta:
      description = "To detect log4shell"
      author = "Anil Yelken"
    strings:
      $a = "jndi:ldap:"
      $b = "jndi:rmi:"
      $c = "jndi:ldaps:"
      $d = "jndi:dns:"
      $e = "%7bjndi:"
      $f = "%24%7bjndi:"
      $g = "%2F%252524%25257Bjndi"
      $h = "jndi:$${lower:"
      $i = "jndi:nis"
      $j = "jndi:nds"
      $k = "jndi:corba"
      $l = "jndi:iiop"
      $m = "{::-l}$${::-d}$${::-a}$${::-p}"
      $n = "base64:JHtqbmRp"
      $o = "base64"
    condition:
       1 of them
    }
