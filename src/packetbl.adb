with Ada.Exceptions; use Ada.Exceptions;
with Nfqueue;
with Packet_Handler;
with Config;
with Ipcache;
with Logger;         use Logger;

procedure Packetbl is
   Nfq : Nfqueue.Netfilter_Queue;
begin
   Config.Handle_Arguments;
   Config.Load_Config;

   for J of Config.Blacklisted_Ips loop
      Ipcache.Cache.Append_Forever (J, Accepted => False);
   end loop;
   for J of Config.Whitelisted_Ips loop
      Ipcache.Cache.Append_Forever (J, Accepted => True);
   end loop;

   Nfq.Open_Queue (0, Packet_Handler.Handle'Access);
   Nfq.Fail_Open;

   Packet_Handler.Initialize (Nfq.Queue);
   Nfq.Handle_Packets;
exception
   when Err : Nfqueue.Error =>
      Log_Abort ("nfqueue exception: " & Exception_Message (Err));
   when Err : others =>
      Log_Abort ("other exception: " & Exception_Message (Err));
end Packetbl;
