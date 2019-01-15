with Nfqueue; use Nfqueue;
with System;

package Packet_Handler is
   task Reporter;

   procedure Initialize (Q : in Queue_Handle);

   function Handle
     (Queue     : in Queue_Handle;
      Nfgenmsg  : in System.Address;
      Nfa       : in Nfq_Data;
      Thread_Hd : in System.Address)
      return Nfq_Bool with
      Convention => C;
end Packet_Handler;
