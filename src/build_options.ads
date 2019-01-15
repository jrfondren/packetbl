package Build_Options is
   Version : constant String := "0.1";

   Default_Config_File : constant String := "/etc/packetbl.conf";

   Max_Requests : constant Positive := 20;
   --  Maximum number of simultaneous DNS requests possible. This
   --  doesn't affect thread count; this controls the size of the
   --  array of requests managed by packet_handler / getaddrinfo_a
   --  (must match nxdomain_helper.c's MAX_REQUESTS)
end Build_Options;
