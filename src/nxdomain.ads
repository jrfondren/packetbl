with System;
with Interfaces.C;

package Nxdomain is
   type Start_Resolve_Status is new Integer;
   type Check_Resolve_Status is new Integer;
   type Await_Resolve_Status is new Integer;
   subtype Gaicb is System.Address;
   type Gaicb_Array is array (Integer range <>) of Gaicb;

   --  the C values can't be used here (as they are when tested below)
   --  without compromising the ability to use them in case 'when'
   --  clauses
   EAI_INPROGRESS : constant Check_Resolve_Status := -100;
   EAI_ALLDONE    : constant Await_Resolve_Status := -103;
   EAI_AGAIN      : constant Await_Resolve_Status := -3;

   function Start_Resolving_At
     (Name    : in     Interfaces.C.char_array;
      Request :    out Gaicb;
      J       : in     Integer)
      return Start_Resolve_Status with
      Import,
      Convention => C,
      Link_Name  => "start_resolving_at";

   function Check_Resolution
     (Request : in Gaicb) return Check_Resolve_Status with
      Import,
      Convention => C,
      Link_Name  => "gai_error";

   type Timespec is record
      Seconds     : Interfaces.C.long;
      Nanoseconds : Interfaces.C.long;
   end record;

   function Await_Resolution
     (Requests : in out Gaicb_Array;
      Items    : in     Natural;
      Timeout  : in     Timespec)
      return Await_Resolve_Status with
      Import,
      Convention => C,
      Link_Name  => "gai_suspend";

private

   Time_T_Bytes : Natural with
      Import,
      Convention => C,
      Link_Name  => "c_time_t_size";
   pragma Assert
     (Interfaces.C.long'Size / Interfaces.C.char'Size = Time_T_Bytes,
      "time_t not equivalent in size to a C 'long'");

   C_Eai_Inprogress : constant Check_Resolve_Status with
      Import,
      Convention => C,
      Link_Name  => "c_eai_inprogress";

   C_Eai_Again : constant Await_Resolve_Status with
      Import,
      Convention => C,
      Link_Name  => "c_eai_again";

   C_Eai_Alldone : constant Await_Resolve_Status with
      Import,
      Convention => C,
      Link_Name  => "c_eai_alldone";

   pragma Assert (EAI_INPROGRESS = C_Eai_Inprogress,
      "EAI_INPROGRESS not as expected");
   pragma Assert (EAI_AGAIN = C_Eai_Again, "EAI_AGAIN not as expected");
   pragma Assert (EAI_ALLDONE = C_Eai_Alldone, "EAI_ALLDONE not as expected");
end Nxdomain;
