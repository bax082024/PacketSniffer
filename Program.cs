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

    static void StartSniffing(string ipAddress, int protocolChoice)
    {
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        socket.Bind(new IPEndPoint(IPAddress.Parse(ipAddress), 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        byte[] inBytes = new byte[] { 1, 0, 0, 0 };
        byte[] outBytes = new byte[4];
        socket.IOControl(IOControlCode.ReceiveAll, inBytes, outBytes);

        Console.WriteLine($"\nListening on {ipAddress}... Press Ctrl+C to stop.\n");

        byte[] buffer = new byte[65535];

        while (true)
        {
            int bytesReceived = socket.Receive(buffer);
            DecodePacket(buffer, bytesReceived, protocolChoice);
            Console.WriteLine("======================================\n");
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