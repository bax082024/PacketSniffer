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

        Console.Write("Enter the network interface to listen on (e.g., 127.0.0.1): ");
        string ipAddress = Console.ReadLine() ?? "127.0.0.1";

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
            Console.WriteLine(Encoding.UTF8.GetString(buffer, 0, bytesReceived));
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



}