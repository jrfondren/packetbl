with GNAT.OS_Lib;
with Ada.Text_IO;  use Ada.Text_IO;
with Interfaces.C; use Interfaces.C;

package body Logger is
   function Syslog
     (Priority : in Integer;
      Format   : in char_array;
      S1       : in char_array)
      return Integer with
      Import,
      Convention => C,
      Link_Name  => "syslog";
   LOG_NOTICE : Integer with
      Import,
      Convention => C,
      Link_Name  => "c_log_notice";
   LOG_ERR : Integer with
      Import,
      Convention => C,
      Link_Name  => "c_log_err";

   procedure Log_Abort (S : in String) is
      Ignore : Integer;
   begin
      Put_Line (Standard_Error, S);
      Ignore := Syslog (LOG_ERR, To_C ("%s"), To_C (S));
      GNAT.OS_Lib.OS_Exit (1);
   end Log_Abort;

   procedure Log (S : in String) is
      Ignore : Integer;
   begin
      Ignore := Syslog (LOG_NOTICE, To_C ("%s"), To_C (S));
   end Log;
end Logger;
