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

    static void DecodePacket(byte[] buffer, int bytesReceived, int protocolChoice)
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

        // Filter logic
        if (protocolChoice != 1 && ((protocolChoice == 2 && protocol != 6) ||
                                     (protocolChoice == 3 && protocol != 17) ||
                                     (protocolChoice == 4 && protocol != 1)))
        {
            return;
        }

        Console.ForegroundColor = protocol switch
        {
            1 => ConsoleColor.Yellow,
            6 => ConsoleColor.Cyan,
            17 => ConsoleColor.Green,
            _ => ConsoleColor.White
        };

        Console.WriteLine("========== Packet Details ==========");
        Console.WriteLine($"Source IP: {sourceIP}");
        Console.WriteLine($"Destination IP: {destIP}");
        Console.WriteLine($"Protocol: {protocolName}");
        Console.WriteLine($"Packet Size: {bytesReceived} bytes");

        if (protocol == 6 || protocol == 17)
        {
            int sourcePort = (buffer[20] << 8) + buffer[21];
            int destPort = (buffer[22] << 8) + buffer[23];
            Console.WriteLine($"Source Port: {sourcePort}");
            Console.WriteLine($"Destination Port: {destPort}");
        }

        Console.ResetColor();
        Console.WriteLine("=====================================\n");
    }




}