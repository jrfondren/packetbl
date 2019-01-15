with Ada.Command_Line; use Ada.Command_Line;
with GNAT.OS_Lib;
with Ada.Text_IO;      use Ada.Text_IO;
with Parse_Results;
with Ada.Characters.Latin_1;
with Ada.Strings.Equal_Case_Insensitive;
with Ada.Exceptions;   use Ada.Exceptions;
with GNAT.Expect;
with GNAT.Regpat;

package body Config is
   package Strings is new Ada.Containers.Indefinite_Vectors (Positive, String);

   package Parser renames Parse_Results;
   procedure Tokenize (S : in String; Parts : in out Strings.Vector);
   procedure Parse (Parts : in out Strings.Vector; Result : out Parser.Result);
   function Parse_Ip (S : in     String;
      Ip                :    out Nfqueue.Ip_Address) return Boolean;
   function Value (Parts : in out Strings.Vector;
      Result             : in     Parser.Result) return String;
   function Value (Parts : in out Strings.Vector;
      Result             : in     Parser.Result) return Nfqueue.Ip_Address;
   function Dot_Prefix (S : in String) return String with
      Pre => S'Length > 0;

   procedure Whitelist_Local_Ips;

   Want_Config_Dump : Boolean := False;

   --  NB. Handle_Arguments is run twice, before and after
   --  Load_Config, so that A) arguments can possibly set which config
   --  file is used, and B) arguments can override settings made in
   --  the config file. If Handle_Arguments becomes expensive or is no
   --  longer idempotent, it'll need to set flags so that Load_Config
   --  can know which settings have already been overridden.
   procedure Handle_Arguments is
      J : Natural := 1;
   begin
      while J <= Argument_Count loop
         if Argument (J) (1) /= '-' or Argument (J)'Length /= 2 then
            Put_Usage;
         end if;
         case Argument (J) (2) is
            when 'h' =>
               Put_Usage;
            when 'v' =>
               Put_Version;
            when 'D' =>
               Want_Config_Dump := True;
            when 'f' =>
               Config_File := To_Unbounded_String (Argument (J + 1));
               J           := J + 1;
            when others =>
               Put_Line (Standard_Error, "invalid flag: -" & Argument (J) (2));
               Put_Usage;
         end case;
         J := J + 1;
      end loop;
   exception
      when Constraint_Error =>
         Put_Usage;
   end Handle_Arguments;

   procedure Load_Config is
      File        : File_Type;
      Got_Error   : Boolean  := False;
      Line_Number : Positive := 1;

      function Image (N : in Positive) return String;

      function Image (N : in Positive) return String is
         S : constant String := Positive'Image (N);
      begin
         return S (2 .. S'Last);
      end Image;
      function Header return String is
        (To_String (Config_File) & ":" & Image (Line_Number) & ": ");
   begin
      Ada.Text_IO.Open
        (File => File, Mode => In_File, Name => To_String (Config_File));
      while not End_Of_File (File) loop
         declare
            Line   : constant String := Get_Line (File);
            Parts  : Strings.Vector;
            Result : Parser.Result;
         begin
            Tokenize (Line, Parts);
            Parse (Parts, Result);
            case Result is
               when Parser.Empty =>
                  null;
               when Parser.Blacklistbl =>
                  Rbl_List.Append
                    (Real_Time_Blacklists, Dot_Prefix (Value (Parts, Result)));
               when Parser.Blacklist =>
                  Ip_List.Append (Blacklisted_Ips, Value (Parts, Result));
               when Parser.Whitelist =>
                  Ip_List.Append (Whitelisted_Ips, Value (Parts, Result));
               when Parser.Error | Parser.Config_File =>
                  Put_Line (Standard_Error, Header & "invalid config");
                  Got_Error := True;
            end case;
         exception
            when Err : Config_Error =>
               Put_Line (Standard_Error, Header & Exception_Message (Err));
               GNAT.OS_Lib.OS_Exit (1);
         end;
         Line_Number := Line_Number + 1;
      end loop;
      if Got_Error then
         GNAT.OS_Lib.OS_Exit (1);
      end if;

      Handle_Arguments;
      --  check arguments (again) to let arguments override config file

      if Natural (Rbl_List.Length (Real_Time_Blacklists)) = 0 then
         Put_Line
           (Standard_Error,
            "invalid config: at least blacklistbl is required");
         GNAT.OS_Lib.OS_Exit (1);
      end if;

      Whitelist_Local_Ips;

      if Want_Config_Dump then
         Dump_Config;
         GNAT.OS_Lib.OS_Exit (1);
      end if;
   end Load_Config;

   procedure Put_Usage is
   begin
      Put_Line
        (Standard_Error,
         "Usage: " & Command_Name & " [-hDv] [-f <config file>]");
      Put_Line (Standard_Error, "  -h     print this help");
      Put_Line (Standard_Error, "  -D     dump configuration");
      Put_Line (Standard_Error, "  -v     print version information");
      GNAT.OS_Lib.OS_Exit (1);
   end Put_Usage;

   procedure Put_Version is
   begin
      Put_Line (Standard_Error, Build_Options.Version);
      GNAT.OS_Lib.OS_Exit (1);
   end Put_Version;

   procedure Tokenize (S : in String; Parts : in out Strings.Vector) is
      Tab    : constant Character := Ada.Characters.Latin_1.HT;
      First  : Natural;
      Second : Natural;
      type States is
        (Want_First, Finish_First, Want_Second, Finish_Second, Want_Nothing);
      State : States := Want_First;
   begin
      Strings.Clear (Parts);
      for J in S'Range loop
         case State is
            when Want_First =>
               case S (J) is
                  when ' ' | Tab =>
                     null;
                  when '#' =>
                     exit; --  empty result
                  when others =>
                     First := J;
                     State := Finish_First;
               end case;
            when Finish_First =>
               case S (J) is
                  when '#' =>
                     Strings.Append (Parts, S (First .. J - 1));
                     exit; --  error result
                  when ' ' | Tab =>
                     Strings.Append (Parts, S (First .. J - 1));
                     State := Want_Second;
                  when others =>
                     null;
               end case;
            when Want_Second =>
               case S (J) is
                  when ' ' | Tab =>
                     null;
                  when '#' =>
                     exit; --  error result
                  when others =>
                     Second := J;
                     State  := Finish_Second;
               end case;
            when Finish_Second =>
               case S (J) is
                  when ' ' | Tab =>
                     Strings.Append (Parts, S (Second .. J - 1));
                     State := Want_Nothing;
                  when '#' =>
                     Strings.Append (Parts, S (Second .. J - 1));
                     exit; --  success (depending on string contents)
                  when others =>
                     null;
               end case;
            when Want_Nothing =>
               case S (J) is
                  when '#' =>
                     exit; --  success
                  when ' ' | Tab =>
                     null;
                  when others =>
                     Strings.Delete_Last (Parts);
                     exit; --  error result
               end case;
         end case;
      end loop;
      if State = Finish_Second then
         Strings.Append (Parts, S (Second .. S'Last));
      end if;
   end Tokenize;

   procedure Parse (Parts : in out Strings.Vector; Result : out Parser.Result)
   is
      function Key_Is (S : in String) return Boolean is
        (Ada.Strings.Equal_Case_Insensitive (S, Parts (1)));
   begin
      case Strings.Length (Parts) is
         when 0 =>
            Result := Parser.Empty;
         when 2 =>
            if Key_Is ("blacklistbl") then
               Result := Parser.Blacklistbl;
            elsif Key_Is ("blacklist") then
               Result := Parser.Blacklist;
            elsif Key_Is ("whitelist") then
               Result := Parser.Whitelist;
            else
               Result := Parser.Error;
            end if;
         when others =>
            Result := Parser.Error;
      end case;
   end Parse;

   function Parse_Ip (S : in     String;
      Ip                :    out Nfqueue.Ip_Address) return Boolean
   is
      type Octet is mod 256;
      subtype Index is Integer range 1 .. 4;
      Digit_Chars : constant String := "0123456789";

      Octets : array (Index) of Natural := (others => 0);
      This   : Index                    := 1;
   begin
      for J in S'Range loop
         if (for some K of Digit_Chars => K = S (J)) then
            Octets (This) :=
              Octets (This) * 10 + Character'Pos (S (J)) - Character'Pos ('0');
         elsif S (J) = '.' and This < Index'Last then
            This := This + 1;
         else
            Ip := 0;
            return False;
         end if;
      end loop;
      if This /= Index'Last then
         Ip := 0;
         return False;
      end if;
      if (for some K of Octets => K > Natural (Octet'Last)) then
         Ip := 0;
         return False;
      end if;
      declare
         use Nfqueue;
      begin
         Ip :=
           Shift_Left (Ip_Address (Octets (1)), 24) +
           Shift_Left (Ip_Address (Octets (2)), 16) +
           Shift_Left (Ip_Address (Octets (3)), 8) + Ip_Address (Octets (4));
         return True;
      end;
   end Parse_Ip;

   function Value (Parts : in out Strings.Vector;
      Result             : in     Parser.Result) return String
   is
   begin
      case Result is
         when Parser.Blacklistbl =>
            return Parts (2);
         when others =>
            raise Config_Error
              with "internal error: looking for a string value for invalid key: " &
              Parts (1);
      end case;
   end Value;

   function Value (Parts : in out Strings.Vector;
      Result             : in     Parser.Result) return Nfqueue.Ip_Address
   is
      Ip : Nfqueue.Ip_Address;
   begin
      case Result is
         when Parser.Blacklist | Parser.Whitelist =>
            if Parse_Ip (Parts (2), Ip) then
               return Ip;
            else
               raise Config_Error with "Expected an IP; got: " & Parts (2);
            end if;
         when others =>
            raise Config_Error
              with "internal error: looking for an IP value for invalid key: " &
              Parts (1);
      end case;
   end Value;

   procedure Dump_Config is
   begin
      for J of Real_Time_Blacklists loop
         Put_Line ("blacklistbl " & J);
      end loop;
      for J of Blacklisted_Ips loop
         Put_Line ("blacklist " & Nfqueue.Image (J));
      end loop;
      for J of Whitelisted_Ips loop
         Put_Line ("whitelist " & Nfqueue.Image (J));
      end loop;
      Put_Line ("#ConfigFile " & To_String (Config_File));
   end Dump_Config;

   procedure Whitelist_Local_Ips is
      use GNAT.Expect;
      use GNAT.Regpat;
      use GNAT.OS_Lib;

      Args : constant Argument_List_Access :=
        Argument_String_To_List ("addr show up");
      Status : aliased Integer;
      Ipaddr : constant String := Get_Command_Output
          (Command   => "ip",
           Arguments => Args (Args'First .. Args'Last),
           Input     => "",
           Status    => Status'Access);

      J, Start : Natural;
      Matches  : Match_Array (0 .. 1);
      Ip       : Nfqueue.Ip_Address;
   begin
      if Status /= 0 then
         raise Config_Error
           with "failed to get local IPs with ``ip addr show up''";
      end if;
      J := 1;
      loop
         --  scan for line ends to apply regex to lines at a time
         Start := J;
         while J < Ipaddr'Last and Ipaddr (J) /= Ada.Characters.Latin_1.LF loop
            J := J + 1;
         end loop;
         Match
           (Compile ("inet ([0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)/"),
            Ipaddr (Start .. J), Matches);
         if Matches (0) /= No_Match then
            if Parse_Ip (Ipaddr (Matches (1).First .. Matches (1).Last), Ip)
            then
               Whitelisted_Ips.Append (Ip);
            end if;
         end if;
         exit when J = Ipaddr'Last;
         J := J + 1;
      end loop;
   end Whitelist_Local_Ips;

   function Dot_Prefix (S : in String) return String is
   begin
      return (if S (S'First) = '.' then S else '.' & S);
   end Dot_Prefix;
end Config;
