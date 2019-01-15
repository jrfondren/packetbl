with System; use System;
with Ipcache;
with Nxdomain;
with Build_Options;
with Interfaces.C;
with Logger; use Logger;
with Config;

package body Packet_Handler is
   type Packet_Info is record
      Id               : Nfqueue.Ip_Id;
      Ip               : Nfqueue.Ip_Address;
      Source_Port      : Natural;
      Destination_Port : Natural;
   end record;
   subtype Index is Positive range 1 .. Build_Options.Max_Requests;
   Requests : Nxdomain.Gaicb_Array (Index) := (others => System.Null_Address);
   Packets  : array (Index) of Packet_Info;
   Queue    : Queue_Handle;

   procedure Initialize (Q : Queue_Handle) is
   begin
      Queue := Q;
   end Initialize;

   protected Buffer is
      entry Insert (Info : in Packet_Info);
      entry Resolve (J : in Index; Verdict : in Netfilter_Verdict);
      entry Await;
   private
      Count : Natural := 0;
   end Buffer;

   protected body Buffer is
      entry Insert (Info : in Packet_Info) when Count <= Index'Last is
         Request : Nxdomain.Gaicb;
         use Nxdomain;
         use Interfaces.C;
      begin
         for J in Requests'Range loop
            if Requests (J) = System.Null_Address then
               if 0 =
                 Nxdomain.Start_Resolving_At
                   (To_C
                      (Reverse_Image (Info.Ip) &
                       Config.Real_Time_Blacklists (1)),
                    Request, J)
               then
                  Requests (J) := Request;
                  Packets (J)  := Info;
                  Count        := Count + 1;
                  exit;
               else
                  raise Nfqueue.Error with "start_resolving_at failed";
               end if;
            end if;
         end loop;
      end Insert;

      entry Resolve (J : in Index; Verdict : in Netfilter_Verdict)
        when Count > 0 is
      begin
         Resolve_Packet (Queue, Packets (J).Id, Verdict);
         Requests (J) := System.Null_Address;
         Count        := Count - 1;
      end Resolve;

      entry Await when Count > 0 is
      begin
         null;
      end Await;
   end Buffer;

   task body Reporter is
      Period : constant Nxdomain.Timespec := (2, 0);
   begin
      loop
         Buffer.Await; --  do nothing when no requests are active
         case Nxdomain.Await_Resolution (Requests, Requests'Length, Period) is
            when Nxdomain.EAI_AGAIN =>
               null;
            when Nxdomain.EAI_ALLDONE | 0 =>
               for J in Requests'Range loop
                  if Requests (J) /= System.Null_Address then
                     case Nxdomain.Check_Resolution (Requests (J)) is
                        when 0 =>
                           Log
                             ("blacklisted " & Nfqueue.Image (Packets (J).Ip));
                           Ipcache.Cache.Append (Packets (J).Ip, False);
                           Buffer.Resolve (J, Nfqueue.NF_DROP);
                        when Nxdomain.EAI_INPROGRESS =>
                           null;
                        when others =>
                           Log ("accepting " & Nfqueue.Image (Packets (J).Ip));
                           Ipcache.Cache.Append (Packets (J).Ip, True);
                           Buffer.Resolve (J, Nfqueue.NF_ACCEPT);
                     end case;
                  end if;
               end loop;
            when others =>
               raise Nfqueue.Error with "await error"; -- should be nxdomain
         end case;
      end loop;
   end Reporter;

   function Handle
     (Queue     : in Queue_Handle;
      Nfgenmsg  : in System.Address;
      Nfa       : in Nfq_Data;
      Thread_Hd : in System.Address)
      return Nfq_Bool
   is
      Info         : Packet_Info;
      Version      : Natural;
      Syn_Flag_Set : Boolean;

      pragma Warnings (Off, Nfgenmsg);
      pragma Warnings (Off, Thread_Hd);

      Found, Accepted : Boolean;
   begin
      Nfqueue.Get_Packet_Info
        (Nfa, Version, Info.Ip, Info.Source_Port, Info.Destination_Port,
         Syn_Flag_Set);
      if (Version = 4 and Syn_Flag_Set)
        and then (1 = Get_Packet_Id (Nfa, Info.Id)) then
         Ipcache.Cache.Seen (Info.Ip, Found, Accepted);
         if Found and Accepted then
            Log ("cache-accepting packet: " & Nfqueue.Image (Info.Ip));
            Accept_Packet (Queue, Info.Id);
         elsif Found and not Accepted then
            Log ("cache-rejecting packet: " & Nfqueue.Image (Info.Ip));
            Reject_Packet (Queue, Info.Id);
         else
            Buffer.Insert (Info);
         end if;
      end if;
      return 0;
   end Handle;
end Packet_Handler;
