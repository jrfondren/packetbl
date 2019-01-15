with Ada.Containers.Doubly_Linked_Lists;
with Ada.Containers.Indefinite_Vectors;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Nfqueue;
with Build_Options;

package Config is
   --  the IP list is unused after it gets fed into ipcache, so a
   --  linked list is fine.  the RBL list is built once and then is
   --  looped over for each packet, so a vector performs better.
   package Ip_List is new Ada.Containers.Doubly_Linked_Lists
     (Nfqueue.Ip_Address, "=" => Nfqueue."=");
   package Rbl_List is new Ada.Containers.Indefinite_Vectors (Positive,
      String);

   Real_Time_Blacklists : Rbl_List.Vector; -- RBLs are always '.'-prefixed
   Blacklisted_Ips      : Ip_List.List;
   Whitelisted_Ips      : Ip_List.List;
   Config_File          : Unbounded_String :=
     To_Unbounded_String (Build_Options.Default_Config_File);

   Config_Error : exception;

   procedure Load_Config;
   procedure Handle_Arguments;
   procedure Dump_Config;
   procedure Put_Usage with
      No_Return;
   procedure Put_Version with
      No_Return;
end Config;
