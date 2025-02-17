using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.IO;

class PacketSniffer
{
    static string logFilePath = "PacketSnifferLog.txt";

    static List<string> sessionLog = new List<string>();
    static List<int> packetSizes = new List<int>();
    static bool colorCodeEnabled = false;

    static string? ipFilter = null;

    static void Main()
    {
        while (true)
        {
            Console.WriteLine("=================================");
            Console.WriteLine("      Packet Sniffer Tool        ");
            Console.WriteLine("=================================\n");
            Console.WriteLine("1. Start Packet Sniffing");
            Console.WriteLine("2. View Session Log");
            Console.WriteLine("3. Reset Session Log");
            Console.WriteLine("4. Filter Settings");
            Console.WriteLine("5. Export Session Log to File");
            Console.WriteLine("6. Load Session Log from File");
            Console.WriteLine("7. Text Color Settings");
            Console.WriteLine("8. View Packet Size Analysis");

            Console.WriteLine("\n8. Exit");
            Console.WriteLine("\nChoose an option (1-8): ");
            string choice = Console.ReadLine() ?? String.Empty;

            switch (choice)
            {
                case "1":
                    StartPacketSniffing();
                    break;
                case "2":
                    DisplaySessionLog();
                    break;
                case "3":
                    ResetSessionLog();
                    break;
                case "4":
                    ConfigureFilterSettings();
                    break;
                case "5":
                    ExportSessionLog();
                    break;
                case "6":
                    LoadSessionLogFromFile();
                    break;
                case "7":
                    SetTextColor();
                    break;
                case "8": 
                    DisplayPacketSizeAnalysis(); 
                    break;
                case "9":
                    Console.WriteLine("Exiting program...");
                    return;
                default:
                    Console.WriteLine("Invalid choice. Please select 1-5.");
                    break;
            }
        }
    }

    static void StartPacketSniffing()
    {
        Console.Write("Enter IP address to filter (or press Enter to capture all): ");
        ipFilter = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(ipFilter))
        {
            ipFilter = null;
        }

        ListNetworkInterfaces();
        Console.Write("Enter the number of the network interface to listen on: ");
        int choice = int.Parse(Console.ReadLine() ?? "1");

        var selectedInterface = NetworkInterface.GetAllNetworkInterfaces()[choice - 1];
        string ipAddress = selectedInterface.GetIPProperties().UnicastAddresses
            .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString()
            ?? "127.0.0.1";

        Console.WriteLine("\nSelect the protocol to filter:");
        Console.WriteLine("1. All Protocols");
        Console.WriteLine("2. TCP");
        Console.WriteLine("3. UDP");
        Console.WriteLine("4. ICMP");
        Console.Write("Enter your choice (1-4): ");
        int protocolChoice = int.Parse(Console.ReadLine() ?? "1");

        sessionLog.Add($"Started sniffing on {selectedInterface.Name} ({ipAddress}) with filter: {GetProtocolName(protocolChoice)}");

        try
        {
            StartSniffing(ipAddress, protocolChoice);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    static void StartSniffing(string ipAddress, int protocolChoice)
    {
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        socket.Bind(new IPEndPoint(IPAddress.Parse(ipAddress), 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        byte[] inBytes = new byte[] { 1, 0, 0, 0 };
        byte[] outBytes = new byte[4];
        socket.IOControl(IOControlCode.ReceiveAll, inBytes, outBytes);

        Console.WriteLine($"\nListening on {ipAddress}... Press 'Q' to stop sniffing and return to menu.\n");

        byte[] buffer = new byte[65535];
        int packetCount = 0;

        while (true)
        {
            if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Q)
            {
                Console.WriteLine("\nStopping packet sniffing...");
                sessionLog.Add("Packet sniffing stopped by user.");
                break;
            }

            int bytesReceived = socket.Receive(buffer);
            packetCount++;
            
            Console.WriteLine($"\nPackets Captured: {packetCount}\n");
            
            var packetDetails = DecodePacket(buffer, bytesReceived, protocolChoice);
            if (!string.IsNullOrEmpty(packetDetails))
            {
                sessionLog.Add(packetDetails);
            }
        }
    }

    static void DisplaySessionLog()
    {
        Console.WriteLine("\n========== Session Log ==========");
        if (sessionLog.Count == 0)
        {
            Console.WriteLine("No logs available.");
        }
        else
        {
            foreach (var entry in sessionLog)
            {
                Console.WriteLine(entry);
            }
        }
        Console.WriteLine("=================================\n");
    }

    static void ResetSessionLog()
    {
        sessionLog.Clear();
        Console.WriteLine("Session log has been reset.\n");
    }

    static string GetProtocolName(int choice)
    {
        return choice switch
        {
            1 => "All Protocols",
            2 => "TCP",
            3 => "UDP",
            4 => "ICMP",
            _ => "Unknown"
        };
    }

    static void ListNetworkInterfaces()
    {
        Console.WriteLine("Available Network Interfaces:");
        int index = 1;

        foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            Console.WriteLine($"{index}. {ni.Name} - {ni.Description} - {ni.NetworkInterfaceType}");
            index++;
        }
    }

    static string DecodePacket(byte[] buffer, int bytesReceived, int protocolChoice)
    {
        var ipHeader = new byte[20];
        Array.Copy(buffer, 0, ipHeader, 0, 20);

        string sourceIP = $"{ipHeader[12]}.{ipHeader[13]}.{ipHeader[14]}.{ipHeader[15]}";
        string destIP = $"{ipHeader[16]}.{ipHeader[17]}.{ipHeader[18]}.{ipHeader[19]}";
        int protocol = ipHeader[9];

        string protocolName = protocol switch
        {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            _ => "Unknown"
        };

        if (protocolChoice != 1 && protocol != GetProtocolNumber(protocolChoice))
        {
            return string.Empty;
        }

        if (ipFilter != null && sourceIP != ipFilter && destIP != ipFilter)
        {
            return string.Empty;
        }

        if (colorCodeEnabled)
        {
            if (protocol == 6) Console.ForegroundColor = ConsoleColor.Cyan;
            else if (protocol == 17) Console.ForegroundColor = ConsoleColor.Yellow;
            else if (protocol == 1) Console.ForegroundColor = ConsoleColor.Green;
        }

        StringBuilder log = new StringBuilder();
        log.AppendLine("========== Packet Details ==========");
        log.AppendLine($"Source IP: {sourceIP}");
        log.AppendLine($"Destination IP: {destIP}");
        log.AppendLine($"Protocol: {protocolName}");
        log.AppendLine($"Packet Size: {bytesReceived} bytes");

        if (protocol == 6 || protocol == 17)
        {
            int sourcePort = (buffer[20] << 8) + buffer[21];
            int destPort = (buffer[22] << 8) + buffer[23];
            log.AppendLine($"Source Port: {sourcePort}");
            log.AppendLine($"Destination Port: {destPort}");
        }

        Console.WriteLine(log.ToString());
        Console.ResetColor();
        Console.WriteLine("=====================================\n");
        return log.ToString();
    }

    static int GetProtocolNumber(int choice)
    {
        return choice switch
        {
            2 => 6,
            3 => 17,
            4 => 1,
            _ => 0
        };
    }

    static void ConfigureFilterSettings()
    {
        Console.WriteLine("\n===== Filter Settings =====");
        Console.WriteLine("1. Toggle Color Code Output");
        Console.WriteLine("2. Back to Main Menu");
        Console.Write("Choose an option: ");

        string option = Console.ReadLine() ?? "2";
        if (option == "1")
        {
            colorCodeEnabled = !colorCodeEnabled;
            Console.WriteLine($"Color Code Output is now {(colorCodeEnabled ? "ENABLED" : "DISABLED")}.");
        }
    }

    static void ExportSessionLog()
    {
        if (sessionLog.Count == 0)
        {
            Console.WriteLine("No session log to export.");
            return;
        }

        Console.WriteLine("Choose export format:");
        Console.WriteLine("1. TXT");
        Console.WriteLine("2. CSV");
        Console.WriteLine("3. JSON");
        Console.Write("Enter choice (1-3): ");
        string formatChoice = Console.ReadLine() ?? "1";

        Console.Write("Enter the path where you want to save the file: ");
        string path = Console.ReadLine() ?? "./SessionLog";

        try
        {
            if (formatChoice == "1")
            {
                File.WriteAllLines(path + ".txt", sessionLog);
                Console.WriteLine("Session log exported as TXT.");
            }
            else if (formatChoice == "2")
            {
                File.WriteAllText(path + ".csv", string.Join(",", sessionLog));
                Console.WriteLine("Session log exported as CSV.");
            }
            else if (formatChoice == "3")
            {
                string json = System.Text.Json.JsonSerializer.Serialize(sessionLog);
                File.WriteAllText(path + ".json", json);
                Console.WriteLine("Session log exported as JSON.");
            }
            else
            {
                Console.WriteLine("Invalid choice.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error exporting session log: {ex.Message}");
        }
    }

    static void LoadSessionLogFromFile()
    {
        Console.Write("Enter the path of the session log file to load: ");
        string filePath = Console.ReadLine() ?? string.Empty;

        if (File.Exists(filePath))
        {
            try
            {
                sessionLog = new List<string>(File.ReadAllLines(filePath));
                Console.WriteLine("Session log loaded successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load session log: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine("File not found. Please check the path and try again.");
        }
    }

    static void SetTextColor()
    {
        Console.WriteLine("\nChoose a text color:");
        Console.WriteLine("1. White");
        Console.WriteLine("2. Cyan");
        Console.WriteLine("3. Yellow");
        Console.WriteLine("4. Green");
        Console.WriteLine("5. Magenta");
        Console.WriteLine("6. Red");
        Console.Write("Enter your choice (1-6): ");

        string colorChoice = Console.ReadLine() ?? "1";

        switch (colorChoice)
        {
            case "1":
                Console.ForegroundColor = ConsoleColor.White;
                break;
            case "2":
                Console.ForegroundColor = ConsoleColor.Cyan;
                break;
            case "3":
                Console.ForegroundColor = ConsoleColor.Yellow;
                break;
            case "4":
                Console.ForegroundColor = ConsoleColor.Green;
                break;
            case "5":
                Console.ForegroundColor = ConsoleColor.Magenta;
                break;
            case "6":
                Console.ForegroundColor = ConsoleColor.Red;
                break;
            default:
                Console.ForegroundColor = ConsoleColor.White;
                break;
        }

        Console.WriteLine($"\nText color set to {Console.ForegroundColor}\n");
    }



}
