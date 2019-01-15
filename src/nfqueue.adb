package body Nfqueue is
   AF_INET : constant Integer with
      Import,
      Convention => C,
      Link_Name  => "c_af_inet";
   NFQNL_COPY_PACKET : constant Character with
      Import,
      Convention => C,
      Link_Name  => "c_nfqnl_copy_packet";

   function Recv
     (Fd     : File_Descriptor;
      Buf    : System.Address;
      Length : Natural;
      Flags  : Integer)
      return Recv_Error with
      Import,
      Convention => C,
      Link_Name  => "recv";

   function Image (Ip : in Ip_Address) return String is
      A : constant String :=
        Ip_Address'Image (Shift_Right (Ip, 24) and 16#ff#);
      B : constant String :=
        Ip_Address'Image (Shift_Right (Ip, 16) and 16#ff#);
      C : constant String := Ip_Address'Image (Shift_Right (Ip, 8) and 16#ff#);
      D : constant String := Ip_Address'Image (Ip and 16#ff#);
   begin
      return A (2 .. A'Last) & "." & B (2 .. B'Last) & "." & C (2 .. C'Last) &
        "." & D (2 .. D'Last);
   end Image;

   function Reverse_Image (Ip : in Ip_Address) return String is
      D : constant String :=
        Ip_Address'Image (Shift_Right (Ip, 24) and 16#ff#);
      C : constant String :=
        Ip_Address'Image (Shift_Right (Ip, 16) and 16#ff#);
      B : constant String := Ip_Address'Image (Shift_Right (Ip, 8) and 16#ff#);
      A : constant String := Ip_Address'Image (Ip and 16#ff#);
   begin
      return A (2 .. A'Last) & "." & B (2 .. B'Last) & "." & C (2 .. C'Last) &
        "." & D (2 .. D'Last);
   end Reverse_Image;

   overriding procedure Finalize (This : in out Netfilter_Queue) is
      Unbind_Error, Close_Error : Nfq_Error;
   begin
      Unbind_Error := Nfq_Unbind_Pf (This.Handle, AF_INET);
      Close_Error  := Nfq_Close (This.Handle);
      if Unbind_Error < 0 then
         raise Error with "nfq_unbind_error failed";
      end if;
      if Close_Error < 0 then
         raise Error with "nfq_close failed";
      end if;
   end Finalize;

   procedure Open_Queue (This : in out Netfilter_Queue; Id : in Integer;
      Callback                : in     Nfq_Callback)
   is
      use System;
   begin
      This.Handle := Nfq_Open;
      if Address (This.Handle) = Null_Address then
         raise Error with "nfq_open failed";
      end if;
      if Nfq_Unbind_Pf (This.Handle, AF_INET) < 0 then
         raise Error with "nfq_unbind_pf failed";
      end if;
      if Nfq_Bind_Pf (This.Handle, AF_INET) < 0 then
         raise Error with "nfq_bind_pf failed";
      end if;
      This.Queue := Nfq_Create_Queue (This.Handle, Id, Callback, Null_Address);
      if Address (This.Queue) = Null_Address then
         raise Error with "nfq_create_queue failed";
      end if;
      if Nfq_Set_Mode (This.Queue, NFQNL_COPY_PACKET, 16#ffff#) < 0 then
         raise Error with "nfq_set_mode failed";
      end if;
   end Open_Queue;

   procedure Handle_Packets (This : in out Netfilter_Queue) is
      Fd       : constant File_Descriptor := Nfq_Fd (This.Handle);
      Received : Recv_Error;
      Buffer   : array (1 .. 16#ffff#) of Character;
   begin
      loop
         Received := Recv (Fd, Buffer'Address, Buffer'Size, 0);
         if Received < 0 then
            raise Error with "recv failed";
         end if;
         if 0 /=
           Nfq_Handle_Packet (This.Handle, Buffer'Address, Natural (Received))
         then
            raise Error with "nfq_handle_packet failed";
         end if;
      end loop;
   end Handle_Packets;

   procedure Get_Packet_Info
     (Data             : in     Nfq_Data;
      Version          :    out Natural;
      Ip               :    out Ip_Address;
      Source_Port      :    out Natural;
      Destination_Port :    out Natural;
      Syn_Flag_Set     :    out Boolean)
   is
      Nfdata   : Nf_Data;
      Syn_Flag : Natural;
   begin
      if 0 = Nfq_Get_Payload (Data, Nfdata) then
         raise Error with "nfq_get_payload failed";
      end if;
      C_Get_Packet_Info
        (Nfdata, Version, Ip, Source_Port, Destination_Port, Syn_Flag);
      Syn_Flag_Set := Syn_Flag /= 0;
   end Get_Packet_Info;

   procedure Accept_Packet (Queue : in Queue_Handle; Id : in Ip_Id) is
      Result : Nfq_Error;
   begin
      Result := Nfq_Set_Verdict (Queue, Id, NF_ACCEPT, 0, System.Null_Address);
      if Result < 0 then
         raise Error with "nfq_set_verdict failed";
      end if;
   end Accept_Packet;

   procedure Reject_Packet (Queue : in Queue_Handle; Id : in Ip_Id) is
      Result : Nfq_Error;
   begin
      Result := Nfq_Set_Verdict (Queue, Id, NF_DROP, 0, System.Null_Address);
      if Result < 0 then
         raise Error with "nfq_set_verdict failed";
      end if;
   end Reject_Packet;

   procedure Resolve_Packet (Queue : in Queue_Handle; Id : in Ip_Id;
      Verdict                      :    Netfilter_Verdict)
   is
      Result : Nfq_Error;
   begin
      Result := Nfq_Set_Verdict (Queue, Id, Verdict, 0, System.Null_Address);
      if Result < 0 then
         raise Error with "nfq_set_verdict failed";
      end if;
   end Resolve_Packet;

   procedure Fail_Open (This : in out Netfilter_Queue) is
      Result : Nfq_Error;
   begin
      Result :=
        Nfq_Set_Queue_Flags
          (This.Queue, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);
      if Result < 0 then
         raise Error with "nfq_set_queue_flags failed";
      end if;
   end Fail_Open;
end Nfqueue;
