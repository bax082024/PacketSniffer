using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.NetworkInformation;
using System.Collections.Generic;

class PacketSniffer
{
    static List<string> sessionLog = new List<string>();

    static void Main()
    {
        while (true)  // Loop to show the main menu
        {
            Console.WriteLine("=================================");
            Console.WriteLine("      Packet Sniffer Tool        ");
            Console.WriteLine("=================================\n");
            Console.WriteLine("1. Start Packet Sniffing");
            Console.WriteLine("2. View Session Log");
            Console.WriteLine("3. Reset Session Log");
            Console.WriteLine("4. Exit");
            Console.Write("Choose an option (1-4): ");
            string choice = Console.ReadLine() ?? "4";

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
                    Console.WriteLine("Exiting program...");
                    return;
                default:
                    Console.WriteLine("Invalid choice. Please select 1-4.");
                    break;
            }
        }
    }

    static void StartPacketSniffing()
    {
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

        while (true)
        {
            if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Q)
            {
                Console.WriteLine("\nStopping packet sniffing...");
                sessionLog.Add("Packet sniffing stopped by user.");
                break;
            }

            int bytesReceived = socket.Receive(buffer);
            var packetDetails = DecodePacket(buffer, bytesReceived, protocolChoice);
            if (!string.IsNullOrEmpty(packetDetails))
            {
                sessionLog.Add(packetDetails);  // Add packet details to the session log
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

        // Filter packets based on user choice
        if (protocolChoice != 1 && protocolChoice != protocol)
        {
            return string.Empty;  // Skip this packet if it doesn't match the filter
        }

        var packetDetails = new StringBuilder();
        packetDetails.AppendLine("========== Packet Details ==========");
        packetDetails.AppendLine($"Source IP: {sourceIP}");
        packetDetails.AppendLine($"Destination IP: {destIP}");
        packetDetails.AppendLine($"Protocol: {protocolName}");
        packetDetails.AppendLine($"Packet Size: {bytesReceived} bytes");

        if (protocol == 6 || protocol == 17)
        {
            int sourcePort = (buffer[20] << 8) + buffer[21];
            int destPort = (buffer[22] << 8) + buffer[23];
            packetDetails.AppendLine($"Source Port: {sourcePort}");
            packetDetails.AppendLine($"Destination Port: {destPort}");
        }

        packetDetails.AppendLine("=====================================");
        Console.WriteLine(packetDetails.ToString());
        return packetDetails.ToString();
    }




}