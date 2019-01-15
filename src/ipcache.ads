with Ada.Containers.Hashed_Maps;
with Nfqueue; use Nfqueue;

package Ipcache is
   Size : constant Natural := 8192;
   subtype Index is Integer range 1 .. Size;
   type Ip_Array is array (Index) of Ip_Address;

   function Hash (Ip : in Ip_Address) return Ada.Containers.Hash_Type is
     (Ada.Containers.Hash_Type'Mod (Ip));
   package Cache_Table is new Ada.Containers.Hashed_Maps
     (Key_Type        => Ip_Address, Element_Type => Boolean, Hash => Hash,
      Equivalent_Keys => "=");

   protected Cache is
      entry Seen (Ip : in     Ip_Address; Found : out Boolean;
         Accepted    :    out Boolean);
      entry Append (Ip : in Ip_Address; Accepted : in Boolean);
      entry Append_Forever (Ip : in Ip_Address; Accepted : in Boolean);
   private
      Table    : Cache_Table.Map;
      Inserted : Ip_Array := (others => 0);
      Fill     : Index    := 1;
   end Cache;
end Ipcache;
