using System;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MDaemonLogFilter
{
    class Program
    {
        static List<string> ips = new List<string>();
        //Wed 2018-04-25 00:00:34: ---------
        static Regex session = new Regex(@"\w{3} \d{4}(-\d{2}){2} (\d{2}:){3} (-){9}");
        //Wed 2018-04-25 00:00:34: Accepting SMTP connection from [220.137.9.244:2767] to [192.168.12.2:25]
        static Regex aceptConn = new Regex(@"\w{3} \d{4}(-\d{2}){2} (\d{2}:){3} Accepting SMTP connection from \[((\d{1,3}\.){3})\d{0,3}:\d+\] to \[((\d{1,3}\.){3})\d{0,3}:\d+\]");

        static void Main(string[] args)
        {
            Console.Write("IP Path: ");
            LoadIPs(new StreamReader(Console.ReadLine()));
            Console.Write("Log Folder: ");
            DirectoryInfo info = new DirectoryInfo(Console.ReadLine());
            foreach (FileInfo elem in info.GetFiles())
                using (StreamReader reader = new StreamReader(elem.FullName))
                    Filter(reader);
        }

        private static void LoadIPs(StreamReader reader)
        {
            string line = "";
            while ((line = reader.ReadLine()) != null)
                ips.Add(line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[0]);
            reader.Close();
        }

        private static void Filter(StreamReader reader)
        {
            string line = "", trace = "", connInfo = "", ip = "";
            while ((line = reader.ReadLine()) != null)
            {
                if (session.IsMatch(line))
                {
                    trace = String.Format("{0}\n{1}\n", line, reader.ReadLine());
                    connInfo = reader.ReadLine();
                    if (connInfo == null)
                        break;
                    trace += connInfo;
                    if (aceptConn.IsMatch(connInfo))
                    {
                        ip = connInfo.Split(' ')[7];
                        ip = ip.Substring(1, ip.Length - 2).Split(':')[0];
                        if (ips.Contains(ip))
                        {
                            while ((line = reader.ReadLine()) != null)
                            {
                                trace += "\n" + line;
                                if (session.IsMatch(line))
                                    break;
                            }
                            using (StreamWriter writer = new StreamWriter(ip + ".txt", true))
                            {
                                foreach (string line2 in trace.Split('\n'))
                                    writer.WriteLine(line2);
                                Console.WriteLine("Added trace for ip = " + ip);
                                writer.WriteLine();
                                writer.WriteLine("***********************************");
                                writer.WriteLine();
                            }
                        }
                    }
                }
            }
        }
    }
}