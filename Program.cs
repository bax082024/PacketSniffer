using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.NetworkInformation;

class PacketSniffer
{
    static void Main()
    {
        Console.WriteLine("=================================");
        Console.WriteLine("      Packet Sniffer Tool        ");
        Console.WriteLine("=================================\n");

        ListNetworkInterfaces();
        Console.Write("Enter the number of the network interface to listen on: ");
        int choice = int.Parse(Console.ReadLine() ?? "1");

        var selectedInterface = NetworkInterface.GetAllNetworkInterfaces()[choice - 1];
        Console.WriteLine($"You selected: {selectedInterface.Name} - {selectedInterface.Description}");

        string ipAddress = selectedInterface.GetIPProperties().UnicastAddresses
            .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString()
            ?? "127.0.0.1";

        try
        {
            StartSniffing(ipAddress);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }


    }

    static void StartSniffing(string ipAddress)
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
            Console.WriteLine($"Packet Captured: {bytesReceived} bytes");
            Console.WriteLine(BitConverter.ToString(buffer, 0, bytesReceived));
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

    static void DecodePacket(byte[] buffer, int bytesReceived)
    {
        // Extract the IP header (first 20 bytes)
        var ipHeader = new byte[20];
        Array.Copy(buffer, 0, ipHeader, 0, 20);

        // Extract Source and Destination IPs from header
        string sourceIP = $"{ipHeader[12]}.{ipHeader[13]}.{ipHeader[14]}.{ipHeader[15]}";
        string destIP = $"{ipHeader[16]}.{ipHeader[17]}.{ipHeader[18]}.{ipHeader[19]}";

        // Protocol field is at byte 9
        int protocol = ipHeader[9];

        string protocolName = protocol switch
        {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            _ => "Unknown"
        };

        Console.WriteLine("========== Packet Details ==========");
        Console.WriteLine($"Source IP: {sourceIP}");
        Console.WriteLine($"Destination IP: {destIP}");
        Console.WriteLine($"Protocol: {protocolName}");
        Console.WriteLine($"Packet Size: {bytesReceived} bytes");

        // If TCP or UDP, print port numbers
        if (protocol == 6 || protocol == 17)
        {
            int sourcePort = (buffer[20] << 8) + buffer[21];
            int destPort = (buffer[22] << 8) + buffer[23];
            Console.WriteLine($"Source Port: {sourcePort}");
            Console.WriteLine($"Destination Port: {destPort}");
        }

        Console.WriteLine("=====================================\n");
    }




}