with Ada.Finalization;
with System;
with Interfaces; use Interfaces;

package Nfqueue is
   --  low level interface. this isn't directly usable without some
   --  additional constants (AF_INET) and functions (recv).

   type Nfq_Handle is new System.Address;
   type Queue_Handle is new System.Address;
   type Nfq_Data is new System.Address;
   type Nf_Data is new System.Address;
   type Nfq_Error is new Integer;
   type Nfq_Bool is new Integer range 0 .. 1;
   type File_Descriptor is new Integer;
   type Recv_Error is new Integer;
   type Ip_Address is new Unsigned_32;
   type Ip_Id is new Integer;
   type Netfilter_Verdict is new Integer;
   type Netfilter_Config is mod 2**32;

   NF_ACCEPT : constant Netfilter_Verdict with
      Import,
      Convention => C,
      Link_Name  => "c_nf_accept";
   NF_DROP : constant Netfilter_Verdict with
      Import,
      Convention => C,
      Link_Name  => "c_nf_drop";

   NFQA_CFG_F_FAIL_OPEN : constant Netfilter_Config with
      Import,
      Convention => C,
      Link_Name  => "c_nfqa_cfg_f_fail_open";

   type Nfq_Callback is access function
     (Queue     : Queue_Handle;
      Nfgenmsg  : System.Address;
      Nfa       : Nfq_Data;
      Thread_Hd : System.Address)
      return Nfq_Bool with
      Convention => C;

   procedure C_Get_Packet_Info
     (Data             : in     Nf_Data;
      Version          :    out Natural;
      Ip               :    out Ip_Address;
      Source_Port      :    out Natural;
      Destination_Port :    out Natural;
      Syn_Flag_Set     :    out Natural) with
      Import,
      Convention => C,
      Link_Name  => "get_packet_info";

   procedure Get_Packet_Info
     (Data             : in     Nfq_Data;
      Version          :    out Natural;
      Ip               :    out Ip_Address;
      Source_Port      :    out Natural;
      Destination_Port :    out Natural;
      Syn_Flag_Set     :    out Boolean);

   function Get_Packet_Id (Nfa : in     Nfq_Data;
      Id                       :    out Ip_Id) return Integer with
      Import,
      Convention => C,
      Link_Name  => "get_packet_id";

   function Nfq_Get_Payload (Nfa : in     Nfq_Data;
      Nfdata                     :    out Nf_Data) return Nfq_Bool with
      Import,
      Convention => C,
      Link_Name  => "nfq_get_payload";

   function Nfq_Open return Nfq_Handle with
      Import,
      Convention => C,
      Link_Name  => "nfq_open";
   function Nfq_Close (Handle : Nfq_Handle) return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_close";
   function Nfq_Unbind_Pf (Handle : Nfq_Handle;
      Pf                          : Integer) return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_unbind_pf";
   function Nfq_Fd (Handle : Nfq_Handle) return File_Descriptor with
      Import,
      Convention => C,
      Link_Name  => "nfq_fd";
   function Nfq_Bind_Pf (Handle : Nfq_Handle;
      Pf                        : Integer) return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_bind_pf";

   function Nfq_Create_Queue
     (Queue    : Nfq_Handle;
      Id       : Integer;
      Callback : Nfq_Callback;
      Data     : System.Address)
      return Queue_Handle with
      Import,
      Convention => C,
      Link_Name  => "nfq_create_queue";

   function Nfq_Set_Mode
     (Queue    : Queue_Handle;
      Mode     : Character;
      Rangearg : Integer)
      return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_set_mode";

   function Nfq_Set_Queue_Maxlen (Queue : Queue_Handle;
      Length                            : Integer) return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_set_queue_maxlen";

   function Nfq_Handle_Packet
     (Handle : Nfq_Handle;
      Buf    : System.Address;
      Len    : Natural)
      return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_handle_packet";

   function Nfq_Set_Verdict
     (Queue   : Queue_Handle;
      Id      : Ip_Id;
      Verdict : Netfilter_Verdict;
      Len     : Natural;
      Buf     : System.Address)
      return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_set_verdict";

   function Nfq_Set_Queue_Flags
     (Queue : Queue_Handle;
      Mask  : Netfilter_Config;
      Flags : Netfilter_Config)
      return Nfq_Error with
      Import,
      Convention => C,
      Link_Name  => "nfq_set_queue_flags";

   Error : exception;

   --  high level interface.

   type Netfilter_Queue is new Ada.Finalization.Limited_Controlled with record
      Handle : Nfq_Handle;
      Queue  : Queue_Handle;
   end record;
   overriding procedure Finalize (This : in out Netfilter_Queue);
   procedure Open_Queue (This : in out Netfilter_Queue; Id : in Integer;
      Callback                : in     Nfq_Callback);
   procedure Fail_Open (This : in out Netfilter_Queue);
   procedure Handle_Packets (This : in out Netfilter_Queue);

   procedure Accept_Packet (Queue : in Queue_Handle; Id : in Ip_Id);
   procedure Reject_Packet (Queue : in Queue_Handle; Id : in Ip_Id);
   procedure Resolve_Packet (Queue : in Queue_Handle; Id : in Ip_Id;
      Verdict                      : in Netfilter_Verdict);

   function Image (Ip : in Ip_Address) return String;
   function Reverse_Image (Ip : in Ip_Address) return String;
end Nfqueue;
