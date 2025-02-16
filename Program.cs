using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

class PacketSniffer
{
    static void Main()
    {
        Console.WriteLine("=================================");
        Console.WriteLine("      Packet Sniffer Tool        ");
        Console.WriteLine("=================================\n");

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
        // Create a raw socket to capture packets
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

        // Bind to the provided IP address
        socket.Bind(new IPEndPoint(IPAddress.Parse(ipAddress), 0));

        // Set the socket to receive all IP packets
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        // Enable promiscuous mode (capture all packets)
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



}