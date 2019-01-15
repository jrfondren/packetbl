package body Ipcache is
   protected body Cache is
      entry Seen (Ip : in     Ip_Address; Found : out Boolean;
         Accepted    :    out Boolean)
        when True is
         C : Cache_Table.Cursor;
      begin
         C := Cache_Table.Find (Table, Ip);
         if Cache_Table.Has_Element (C) then
            Found    := True;
            Accepted := Cache_Table.Element (C);
         else
            Found    := False;
            Accepted := False;
         end if;
      end Seen;

      entry Append (Ip : in Ip_Address; Accepted : in Boolean) when True is
         C : Cache_Table.Cursor;
      begin
         C := Cache_Table.Find (Table, Ip);
         if not Cache_Table.Has_Element (C) then
            Cache_Table.Insert (Table, Ip, Accepted);
            if Inserted (Fill) /= 0 then
               C := Cache_Table.Find (Table, Inserted (Fill));
               if Cache_Table.Has_Element (C) then
                  Cache_Table.Delete (Table, C);
               end if;
            end if;
            Inserted (Fill) := Ip;
            Fill            := Fill + 1;
         end if;
      end Append;

      entry Append_Forever (Ip : in Ip_Address; Accepted : in Boolean)
        when True is
         C : Cache_Table.Cursor;
      begin
         C := Cache_Table.Find (Table, Ip);
         if not Cache_Table.Has_Element (C) then
            Cache_Table.Insert (Table, Ip, Accepted);
         end if;
      end Append_Forever;
   end Cache;
end Ipcache;
