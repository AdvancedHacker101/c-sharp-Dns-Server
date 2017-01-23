using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Xml;
using System.IO;

namespace dnsServer
{

    public class Client
    {
        UdpClient client;
        public IPEndPoint ep;

        public void start()
        {
            if (ep == null) ep = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53);
            Console.WriteLine("Endpoint Created!");
            client = new UdpClient();
            client.Connect(ep);
            Console.WriteLine("UDP Connected");
        }

        public byte[] directRead()
        {
            byte[] msg = client.Receive(ref ep);
            return msg;
        }

        public void read()
        {
            Console.WriteLine("Initializing Read");
            client.BeginReceive(new AsyncCallback(recvAsync), null);
            Console.WriteLine("Read async started");
        }

        private void recvAsync(IAsyncResult ar)
        {
            byte[] data = client.EndReceive(ar, ref ep);
            Console.WriteLine("Data Size: " + data.Length.ToString());
            string message = Encoding.ASCII.GetString(data);
            Console.WriteLine("Data Payload: " + message);
            client.BeginReceive(new AsyncCallback(recvAsync), null);
        }

        public void write(String message)
        {
            byte[] msg = Encoding.ASCII.GetBytes(message);
            client.Send(msg, msg.Length);
            Console.WriteLine("[" + msg.Length.ToString() + " bytes] Data sent!");
        }

        public void write(byte[] msg)
        {
            client.Send(msg, msg.Length);
            Console.WriteLine("[" + msg.Length.ToString() + " bytes] Data sent!");
        }
    }

    public class Server
    {
        IPEndPoint ep;
        UdpClient listener;
        List<IPEndPoint> clients = new List<IPEndPoint>();
        reqEditor editor = new reqEditor();

        public void start()
        {
            ep = new IPEndPoint(IPAddress.Any, 53);
            listener = new UdpClient(ep);
            Console.WriteLine("Udp Listener started");
            editor.loadXML("test.xml");
            editor.printXML();
        }

        public void read()
        {
            Console.WriteLine("Setup started");
            listener.BeginReceive(new AsyncCallback(recvAsync), null);
            Console.WriteLine("Async recv started");
        }

        private void recvAsync(IAsyncResult ar)
        {
            IPEndPoint currentClient = new IPEndPoint(IPAddress.Any, 0);
            byte[] cMsg = listener.EndReceive(ar, ref currentClient);
            Console.WriteLine("[" + cMsg.Length.ToString() + " bytes] Data Size");
            string plain = Encoding.ASCII.GetString(cMsg);
            Console.WriteLine("Data Payload: \n");
            int counter = 0;
            string fullDump = "";
            foreach (int byt in cMsg)
            {
                if (counter > 15)
                {
                    counter = 0;
                    Console.Write("\n");
                }
                string hex = byt.ToString("X");
                if (hex.Length == 1) hex = "0" + hex;
                Console.Write(hex);
                Console.Write(" ");
                fullDump += hex;
                counter++;
            }
            dnsRequest request = new dnsRequest();
            request.serialize(fullDump);
            //Mofify request here
            editor.setRequest(request);
            request = editor.runXML();
            Console.WriteLine("\nDeserialize test\n");
            string payload = request.deserialize(request);
            formatHex(payload);
            byte[] entropy = request.ToArray(payload);
            Client google = new Client();
            google.start();
            google.write(entropy);
            byte[] resp = google.directRead();
            dnsRequest response = new dnsRequest();
            string hx = byteToHex(resp);
            response.serialize(hx);
            editor.setRequest(response);
            response = editor.runXML();
            Console.WriteLine(response.ToString());
            string strResponse = response.deserialize(response);
            formatHex(strResponse);
            byte[] rsp = response.ToArray(strResponse);
            write(rsp, currentClient);
            Console.WriteLine("Dns Req - Rsp sequence done");
            if (!clients.Contains(currentClient)) clients.Add(currentClient);
            listener.BeginReceive(new AsyncCallback(recvAsync), null);
        }

        private String byteToHex(byte[] cMsg)
        {
            int counter = 0;
            string fullDump = "";
            foreach (int byt in cMsg)
            {
                if (counter > 15)
                {
                    counter = 0;
                    Console.Write("\n");
                }
                string hex = byt.ToString("X");
                if (hex.Length == 1) hex = "0" + hex;
                Console.Write(hex);
                Console.Write(" ");
                fullDump += hex;
                counter++;
            }

            return fullDump;
        }

        private void formatHex(string input)
        {
            int counter = 0;
            int is2 = 0;
            for (int i = 0; i < input.Length; i++)
            {
                if (counter > 31)
                {
                    counter = 0;
                    Console.Write("\n");
                }

                Console.Write(input[i]);

                if (is2 == 1)
                {
                    is2 = -1;
                    Console.Write(" ");
                }
                counter++;
                is2++;
            }
        }

        public void write(byte[] msg, IPEndPoint ep)
        {
            listener.Send(msg, msg.Length, ep);
        }

        public void write(String message, int clientID = 0)
        {
            byte[] sMsg = Encoding.ASCII.GetBytes(message);
            if (clientID > clients.Count)
            {
                Console.WriteLine("Invalid Client ID: " + clientID.ToString());
                return;
            }
            listener.Send(sMsg, sMsg.Length, clients[clientID]);
            Console.WriteLine("Data Sent: " + sMsg.Length.ToString() + " bytes");
        }
    }
    
    public class reqEditor
    {
        dnsRequest req;
        bool authoritiveProtection = false;
        List<String> blackList = new List<String>();
        List<String> redirect = new List<String>();

        public reqEditor()
        {

        }

        public reqEditor(dnsRequest request)
        {
            req = request;
        }

        public void setRequest(dnsRequest request)
        {
            req = request;
        }

        public void loadXML(string xmlfile)
        {
            if (File.Exists(xmlfile))
            {
                using (XmlReader xml = XmlReader.Create(xmlfile))
                {

                    while (xml.Read())
                    {
                        if (xml.IsStartElement())
                        {
                            if (xml.Name == "drop")
                            {
                                blackList.Add(xml.GetAttribute("hostname"));
                            }
                            else if (xml.Name == "redirect")
                            {
                                redirect.Add(xml.GetAttribute("from") + ":" + xml.GetAttribute("to"));
                            }
                        }
                    }

                    Console.WriteLine("Configuration Loaded!");
                }
            }
        }

        public dnsRequest runXML()
        {
            dnsRequest copy = req;


            if (authoritiveProtection)
            {
                List<int> auth = new List<int>();
                int t = 0;
                foreach (dnsRequest.GeneralRecord gr in copy.records)
                {
                    if (gr.resource_type == dnsRequest.DnsResourceType.Authority)
                    {
                        auth.Add(t);
                    }

                    t++;
                }

                foreach (int i in auth)
                {
                    copy.records.RemoveAt(i);
                }

                authoritiveProtection = false;
            }

            foreach (string item in blackList)
            {
                if (copy.response == (int)dnsRequest.DnsResponse.response)
                {
                    bool removeResp = true;

                    foreach (dnsRequest.GeneralRecord gr in copy.records)
                    {
                        if (gr.rType == (int)dnsRequest.DnsResourceType.Query)
                        {
                            if (gr.rName == item)
                            {
                                removeResp = true;
                                copy.return_code = (int)dnsRequest.DnsReturnCodes.NonExistentDomain;
                            }
                        }
                    }

                    if (removeResp)
                    {
                        List<dnsRequest.GeneralRecord> lcpy = new List<dnsRequest.GeneralRecord>();
                        foreach (dnsRequest.GeneralRecord r in lcpy)
                        {
                            if (r.resource_type != (int)dnsRequest.DnsResourceType.Query)
                            {
                                copy.records.Remove(r);
                            }
                        }

                        copy.additional_resource_record_count = 0;
                        copy.answer_resource_record_count = 0;
                        copy.authority_resource_record_count = 0;
                        break;
                    }
                }
            }

            foreach (string item in redirect)
            {
                if (copy.response == (int)dnsRequest.DnsResponse.response)
                {
                    int i = 0;
                    bool canBreak = false;
                    List<int> authoritive = new List<int>();

                    foreach (dnsRequest.GeneralRecord gr in copy.records)
                    {
                        if (gr.resource_type == dnsRequest.DnsResourceType.Answer && copy.return_code == (int)dnsRequest.DnsReturnCodes.Success)
                        {
                            if (copy.records[i].rName == item.Split(':')[0])
                            {
                                ((dnsRequest.AnswerRecord)copy.records[i]).result = item.Split(':')[1];
                                canBreak = true;
                            }
                        }

                        i++;
                    }

                    if (canBreak)
                    {
                        authoritiveProtection = true;
                        break;
                    }
                }
            }

            return copy;
        }

        public void printXML()
        {
            Console.WriteLine("===============Start of Rules===============");

            foreach (string item in blackList)
            {
                Console.WriteLine("Drop: " + item);
            }

            foreach (string item in redirect)
            {
                string from = item.Split(':')[0];
                string to = item.Split(':')[1];
                Console.WriteLine("Redirect: " + from + " to " + to);
            }

            Console.WriteLine("===============End of Rules===============");
        }
    }


    public class dnsRequest
    {
        public int reqCount = 0;
        public int AuthAnswer = -1;
        public int opcode = -1;
        public int response = -1;
        public int truncation = -1;
        public int recursion_desired = -1;
        public int recursion_available = -1; //Server side only (response)
        public const int reserved = 0;
        public int return_code = -1; //Server side only (response)
        public int question_resource_record_count = -1;
        public int answer_resource_record_count = -1; //Server side only (response)
        public int authority_resource_record_count = -1; //Server side only (response)
        public int additional_resource_record_count = -1; //Server side only (response)
        public string lookup_hostname = "";
        public int question_type = -1;
        public int question_class = -1;
        public List<GeneralRecord> records = new List<GeneralRecord>();
        
        public class GeneralRecord
        {
            public int rClass;
            public int rType;
            public string rName;
            public DnsResourceType resource_type;
        }

        public class AuthoritiveRecord : GeneralRecord
        {
            public int ttl; //ttl = time to live
            public int dataLength;
            public string primaryNS; //NS = nameServer
            public string authorityMailbox;
            public int serialNum;
            public int refreshInterval;
            public int retryInterval;
            public int expireLimit;
            public int minttl;
        }

        public class AnswerRecord : GeneralRecord
        {
            public int ttl;
            public int dataLength;
            public string result; //Address (or hostname if the request is PTR)
            public string ipv6Hex;
        }

        public class AdditionalRecord : GeneralRecord
        {
            public string hexDump;
        }

        public void serialize(String hexDump)
        {
            //Dns request parts reference: https://technet.microsoft.com/en-us/library/dd197470%28v=ws.10%29.aspx

            //Get Request Count
            reqCount = int.Parse(hexDump.Substring(0, 4), System.Globalization.NumberStyles.HexNumber); //.Substring(2).Substring(0, 2)
            //Get the request flags
            string ff = hexDump.Substring(4).Substring(0, 4); //ff = flagsField
            string binary = Convert.ToString(Convert.ToInt32(ff, 16), 2);
            binary = binary.PadLeft(16, '0');
            /* Response = 1 bit
             * OpCode = 4 bit
             * Authoritive answer = 1 bit
             * truncation = 1 bit
             * rec desired = 1 bit
             * rec avail = 1 bit
             * reserved = 3 bit (const 0)
             * return code = 4 bit
             */
            response = Convert.ToInt32(binary.Substring(0, 1), 2);
            opcode = Convert.ToInt32(binary.Substring(1, 4), 2);
            AuthAnswer = Convert.ToInt32(binary.Substring(5, 1), 2);
            truncation = Convert.ToInt32(binary.Substring(6, 1), 2);
            recursion_desired = Convert.ToInt32(binary.Substring(7, 1), 2);
            if ((DnsResponse)response != DnsResponse.request)
            {
                recursion_available = Convert.ToInt32(binary.Substring(8, 1), 2);
                return_code = Convert.ToInt32(binary.Substring(12, 4), 2);
            }
            else
            {
                recursion_available = 0;
                return_code = 0;
            }
            /*int flagCode = int.Parse(ff, System.Globalization.NumberStyles.HexNumber);
            response = (flagCode >> 15);
            if (response != 0) //Message is a request
            {
                return_code = (flagCode >> 3);
                recursion_available = (flagCode >> 7);
            }
            else
            {
                return_code = 0;
                recursion_available = 0;
            }
            recursion_desired = (flagCode >> 8);
            truncation = (flagCode >> 9);
            AuthAnswer = (flagCode >> 10);
            opcode = (flagCode >> 14);*/
            //Get resource record counts
            question_resource_record_count = int.Parse(hexDump.Substring(8).Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
            answer_resource_record_count = int.Parse(hexDump.Substring(12).Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
            authority_resource_record_count = int.Parse(hexDump.Substring(16).Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
            additional_resource_record_count = int.Parse(hexDump.Substring(20).Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
            int questionStart = 24;
            for (int q = 0; q < question_resource_record_count; q++)
            {
                //Get Question hostname
                string question = hexDump.Substring(questionStart);
                int bytesRead = 0;
                GeneralRecord queryResource = (GeneralRecord)serializeRecords(question, DnsResourceType.Query, out bytesRead, 0, hexDump);
                questionStart += bytesRead;
                records.Add(queryResource);
            }

            for (int q = 0; q < answer_resource_record_count; q++)
            {
                //Get Question hostname
                string question = hexDump.Substring(questionStart);
                int bytesRead = 0;
                AnswerRecord answerResource = (AnswerRecord)serializeRecords(question, DnsResourceType.Answer, out bytesRead, 0, hexDump);
                questionStart += bytesRead;
                records.Add(answerResource);
            }

            for (int q = 0; q < authority_resource_record_count; q++)
            {
                //Get Question hostname
                string question = hexDump.Substring(questionStart);
                int bytesRead = 0;
                AuthoritiveRecord authorityResource = (AuthoritiveRecord)serializeRecords(question, DnsResourceType.Authority, out bytesRead, 0, hexDump);
                questionStart += bytesRead;
                records.Add(authorityResource);
            }

            for (int q = 0; q < additional_resource_record_count; q++)
            {
                //Get Question hostname
                string question = hexDump.Substring(questionStart);
                int bytesRead = 0;
                AdditionalRecord additionalResource = (AdditionalRecord)serializeRecords(question, DnsResourceType.Additional, out bytesRead, 0, hexDump);
                questionStart += bytesRead;
                records.Add(additionalResource);
            }

            //Serialization Completed!! yay :)
            Console.WriteLine("Serialized!");
        }

        private object serializeRecords(String question, DnsResourceType rType, out int questionStart, int startingQStart, String fullDump)
        {
            if (rType == DnsResourceType.Query)
            {
                GeneralRecord gr = new GeneralRecord();
                gr.resource_type = rType;
                String rest = "";
                int iTracker = 0;
                lookup_hostname = serializeLabel(out iTracker, question, out rest);
                //Get Question type and class
                string lastPart = question.Substring(iTracker).Substring(2);
                startingQStart += iTracker + 2;
                question_type = int.Parse(lastPart.Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
                question_class = int.Parse(lastPart.Substring(4, 4), System.Globalization.NumberStyles.HexNumber);
                startingQStart += 8;
                gr.rName = lookup_hostname;
                gr.rClass = question_class;
                gr.rType = question_type;
                //records.Add(query);
                questionStart = startingQStart;
                return gr;
            }
            else if (rType == DnsResourceType.Answer)
            {
                AnswerRecord ar = new AnswerRecord();
                ar.resource_type = rType;
                String rest = "";
                int iTracker = 0;
                //Read the pointer pointing to the original address
                string pointer = question.Substring(2, 2);
                int offset = int.Parse(pointer, System.Globalization.NumberStyles.HexNumber);
                string hostLabel = fullDump.Substring(offset * 2);
                lookup_hostname = serializeLabel(out iTracker, hostLabel, out rest);
                //Get Question type and class
                string lastPart = question.Substring(4);
                question_type = int.Parse(lastPart.Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
                question_class = int.Parse(lastPart.Substring(4, 4), System.Globalization.NumberStyles.HexNumber);
                ar.rName = lookup_hostname;
                ar.rClass = question_class;
                ar.rType = question_type;
                ar.ttl = int.Parse(lastPart.Substring(8, 8), System.Globalization.NumberStyles.HexNumber);
                ar.dataLength = int.Parse(lastPart.Substring(16, 4), System.Globalization.NumberStyles.HexNumber);
                if (ar.dataLength == 4 || ar.dataLength == 16) ar.result = serializeIP(lastPart.Substring(20, ar.dataLength * 2));  //ipv4 or ipv6 address
                else ar.result = serializeLabel(out iTracker, lastPart.Substring(20, ar.dataLength * 2), out rest);
                if (ar.dataLength == 16)
                {
                    ar.ipv6Hex = lastPart.Substring(20, ar.dataLength * 2);
                }
                startingQStart += 20 + ar.dataLength * 2;
                questionStart = startingQStart;
                return ar;
            }
            else if (rType == DnsResourceType.Authority)
            {      
                AuthoritiveRecord ar = new AuthoritiveRecord();
                ar.resource_type = rType;
                String rest = "";
                int iTracker = 0;
                string lastPart = "";
                int sub = 0;
                //Get pointer
                if (question.Substring(0, 2) == "00") ar.rName = "<Root>";
                else
                {
                    string pointer = question.Substring(0, 4);
                    string p1 = pointer.Substring(0, 2);
                    string p2 = pointer.Substring(2);
                    int i1 = int.Parse(p1, System.Globalization.NumberStyles.HexNumber);
                    int i2 = int.Parse(p2, System.Globalization.NumberStyles.HexNumber);
                    string binary = Convert.ToString((i1 + i2), 2);
                    binary = binary.Substring(2);
                    int offset = Convert.ToInt32(binary, 2);
                    string hostLabel = fullDump.Substring(offset);
                    if (hostLabel.StartsWith("00")) hostLabel = hostLabel.Substring(2);
                    lookup_hostname = serializeLabel(out iTracker, hostLabel, out rest);
                    lastPart = question.Substring(4);
                    sub = 4;
                }
                if (lastPart == "") lastPart = question.Substring(2);
                if (sub == 0) sub = 2;
                question_type = int.Parse(lastPart.Substring(0, 4), System.Globalization.NumberStyles.HexNumber);
                question_class = int.Parse(lastPart.Substring(4, 4), System.Globalization.NumberStyles.HexNumber);
                ar.rName = lookup_hostname;
                ar.rType = question_type;
                ar.rClass = question_class;
                ar.ttl = int.Parse(lastPart.Substring(8, 8), System.Globalization.NumberStyles.HexNumber);
                ar.dataLength = int.Parse(lastPart.Substring(16, 4), System.Globalization.NumberStyles.HexNumber);
                string dataPart = lastPart.Substring(20);
                String[] parts = multiSplit("00", dataPart);
                string pDnsSrv = parts[0];
                string rAuthMail = parts[1];
                int pdnsl = 0;
                if (!containsPointer(pDnsSrv) && !pDnsSrv.EndsWith("00"))
                {
                    pDnsSrv += "00";
                    pdnsl += 2;
                }
                ar.primaryNS = serializeLabel(out iTracker, pDnsSrv, out rest, fullDump);
                pdnsl += iTracker;
                string afterPart = "";
                if (containsPointer(pDnsSrv))
                {
                    bool ismailPointer = containsPointer(rest);
                    ar.authorityMailbox = serializeLabel(out iTracker, rest, out rest, fullDump);
                    pdnsl += ar.authorityMailbox.Length * 2 + 4;
                    if (ismailPointer)
                    {
                        pdnsl -= (ar.authorityMailbox.Length * 2 + 4);
                        pdnsl += iTracker;
                        afterPart = question.Substring(20 + pdnsl + sub);
                    }
                    else
                    {
                        afterPart = question.Substring(20 + pdnsl + sub);
                    }
                }
                else
                {
                    bool ismailPointer = containsPointer(rAuthMail);
                    ar.authorityMailbox = serializeLabel(out iTracker, rAuthMail, out rest, fullDump);
                    pdnsl += ar.authorityMailbox.Length * 2 + 4;
                    if (ismailPointer)
                    {
                        pdnsl -= (ar.authorityMailbox.Length * 2 + 4);
                        pdnsl += iTracker;
                        afterPart = question.Substring(20 + pdnsl + sub);
                    }
                    else
                    {
                        afterPart = question.Substring(20 + pdnsl + sub);
                    }
                }
                ar.serialNum = int.Parse(afterPart.Substring(0, 8), System.Globalization.NumberStyles.HexNumber);
                ar.refreshInterval = int.Parse(afterPart.Substring(8, 8), System.Globalization.NumberStyles.HexNumber);
                ar.retryInterval = int.Parse(afterPart.Substring(16, 8), System.Globalization.NumberStyles.HexNumber);
                ar.expireLimit = int.Parse(afterPart.Substring(24, 8), System.Globalization.NumberStyles.HexNumber);
                ar.minttl = int.Parse(afterPart.Substring(32, 8), System.Globalization.NumberStyles.HexNumber);
                startingQStart += 24 + pdnsl + 40;
                questionStart = startingQStart;
                return ar;
            }
            else
            {
                AdditionalRecord ar = new AdditionalRecord();
                ar.resource_type = rType;
                ar.hexDump = question;
                ar.rName = "-1";
                ar.rType = -1;
                ar.rClass = -1;
                questionStart = question.Length;
                return ar;
            }
        }

        private bool containsPointer(string check)
        {
            bool isPointer = false;
            int skip = 0;

            for (int i = 0; i < check.Length; i++ )
            {
                if (skip == 1)
                {
                    skip = 0;
                    continue;
                }
                if (skip == 0) skip = 1;
                if ((i + 1) >= check.Length) break;
                string currentBit = check[i].ToString() + check[i + 1].ToString();
                if (currentBit == "C0")
                {
                    isPointer = true;
                    break;
                }
            }

            return isPointer;
        }

        private string serializeIP(string hxDump)
        {
            string ip = "";
            
            if (hxDump.Length == 8)
            {
                for (int i = 0; i < 4; i++)
                {
                    string octet = hxDump.Substring(2 * i, 2);
                    ip += int.Parse(octet, System.Globalization.NumberStyles.HexNumber) + ".";
                }

                ip = ip.Substring(0, ip.Length - 1);
            }
            else if (hxDump.Length == 32)
            {
                bool ignoredZeros = false;

                for (int i = 0; i < 4; i++)
                {
                    string part = hxDump.Substring(4 * i, 4);
                    if (part != "0000")
                    {
                        if (ignoredZeros)
                        {
                            ip += ":";
                            ignoredZeros = false;
                        }

                        ip += part + ":";
                    }
                    else
                    {
                        ignoredZeros = true;
                    }
                }

                ip = ip.Substring(0, ip.Length - 1);
            }

            return ip;
        }

        private string serializeLabel(out int length, string question, out string rest, string full = "")
        {
            string lcHost = "";
            int iTracker = 0;
            int isChecked = 0;
            int tempTracker = 0;
            int readUntil = -1;
            bool isFirstCheck = true;
            for (int i = 0; i < question.Length; i++)
            {
                if (isChecked == 1)
                {
                    isChecked = 0;
                    continue;
                }

                string currentBit = question[i].ToString() + question[i + 1].ToString();

                if (currentBit == "00")
                {
                    iTracker *= 2;
                    break;
                }

                if (currentBit == "C0")
                {
                    //Pointer found
                    lcHost += ".";
                    int offset = int.Parse(question[i + 2].ToString() + question[i + 3].ToString(), System.Globalization.NumberStyles.HexNumber) * 2;
                    string data = full.Substring(offset);
                    int dataLength = 0;
                    string afterText = "";
                    string lastPart = serializeLabel(out dataLength, data, out afterText, full);
                    lcHost += lastPart;
                    iTracker += 2;
                    iTracker *= 2;
                    break;
                }

                int code = int.Parse(currentBit, System.Globalization.NumberStyles.HexNumber);

                if (isChecked == 0)
                {
                    isChecked = 1;
                }

                if (isFirstCheck)
                {
                    readUntil = code;
                    isFirstCheck = false;
                    iTracker++;
                    continue;
                }
                else if (tempTracker == readUntil)
                {
                    lcHost += ".";
                    readUntil = code;
                    tempTracker = 0;
                    iTracker++;
                    continue;
                }
                else
                {
                    lcHost += (char)code;
                }

                iTracker++;
                tempTracker++;
            }
            length = iTracker;
            rest = question.Substring(length);
            return lcHost;
        }

        private String[] multiSplit(String splitter, String text) //hex split
        {
            List<String> result = new List<String>();

            int lastSplit = 0;
            int skip = 0;

            for (int i = 0; i < text.Length; i++)
            {
                if (skip == 1)
                {
                    skip = 0;
                    continue;
                }

                if (skip == 0)
                {
                    skip = 1;
                }

                string currentBit = text[i].ToString() + text[i + 1].ToString();
                if (currentBit == splitter)
                {
                    if (lastSplit != 0) lastSplit += 1;
                    String add = text.Substring(lastSplit, i - lastSplit);
                    result.Add(add);
                    lastSplit = i - lastSplit + 1;
                }
            }

            return result.ToArray();
        }

        private String deserializeLabel(String labels)
        {
            String des = "";
            String flush = "";
            //bool first = true;
            int partCounter = 0;

            for (int i = 0; i < labels.Length; i++ )
            {
                if (labels[i] == '.')
                {
                    flush = (partCounter).ToString("X2") + flush;
                    des += flush;
                    flush = "";
                    partCounter = 0;
                    continue;
                }


                byte chr = Encoding.ASCII.GetBytes(labels[i].ToString())[0];
                int ichr = Convert.ToInt32(chr);
                string xchr = ichr.ToString("X2");
                flush += xchr;
                partCounter++;

                if ((i + 1) == labels.Length)
                {
                    flush = (partCounter).ToString("X2") + flush;
                    des += flush;
                    flush = "";
                    partCounter = 0;
                    continue;
                }
            }

            return des;
        }

        private String deserializeIP(String ip, String ipv6 = "")
        {
            String des = "";

            if (ip.Contains("."))
            {
                foreach (String octet in ip.Split('.'))
                {
                    des += int.Parse(octet).ToString("X2");
                }
            }
            else if (ip.Contains(":") && ipv6 != "" && ipv6 != null)
            {
                des = ipv6;
            }

            return des;
        }

        public String deserialize(dnsRequest request)
        {
            string result = "";
            //Append request count
            result += reqCount.ToString("X4");
            //Build and append flags
            int flags = 0;
            flags = (response << 15) | (opcode << 11) | (AuthAnswer << 10) | (truncation << 9) | (recursion_desired << 8) | (recursion_available << 7) | (reserved << 4) | return_code;
            result += flags.ToString("X4");
            //Append resource record counts
            result += question_resource_record_count.ToString("X4");
            result += answer_resource_record_count.ToString("X4");
            result += authority_resource_record_count.ToString("X4");
            result += additional_resource_record_count.ToString("X4");

            //Deserialize records

            foreach (GeneralRecord gr in request.records)
            {
                if (gr.resource_type == DnsResourceType.Query)
                {
                    string name = deserializeLabel(gr.rName);
                    string type = gr.rType.ToString("X4");
                    string rclass = gr.rClass.ToString("X4");
                    result += name;
                    result += "00";
                    result += type;
                    result += rclass;
                }
                if (gr.resource_type == DnsResourceType.Answer)
                {
                    AnswerRecord ar = (AnswerRecord)gr;
                    string name = deserializeLabel(ar.rName);
                    string type = ar.rType.ToString("X4");
                    string rclass = ar.rClass.ToString("X4");
                    string ttl = ar.ttl.ToString("X8");
                    string aresult = deserializeIP(ar.result, ar.ipv6Hex);
                    string length = (aresult.Length / 2).ToString("X4");
                    result += name + "00";
                    result += type;
                    result += rclass;
                    result += ttl;
                    result += length;
                    result += aresult;
                }
                if (gr.resource_type == DnsResourceType.Authority)
                {
                    AuthoritiveRecord ar = (AuthoritiveRecord)gr;
                    string name = deserializeLabel(ar.rName);
                    string type = ar.rType.ToString("X4");
                    string rclass = ar.rClass.ToString("X4");
                    string ttl = ar.ttl.ToString("X8");
                    string pDnsSrv = deserializeLabel(ar.primaryNS);
                    string mailbox = deserializeLabel(ar.authorityMailbox);
                    string serial = ar.serialNum.ToString("X8");
                    string refresh = ar.refreshInterval.ToString("X8");
                    string retry = ar.retryInterval.ToString("X8");
                    string expire = ar.expireLimit.ToString("X8");
                    string minttl = ar.minttl.ToString("X8");
                    string length = ((pDnsSrv.Length + mailbox.Length + 40) / 2).ToString("X4");
                    result += name + "00";
                    result += type;
                    result += rclass;
                    result += ttl;
                    result += length;
                    result += pDnsSrv + "00";
                    result += mailbox + "00";
                    result += serial;
                    result += refresh;
                    result += retry;
                    result += expire;
                    result += minttl;
                }
                if (gr.resource_type == DnsResourceType.Additional)
                {
                    AdditionalRecord ar = (AdditionalRecord)gr;
                    result += ar.hexDump;
                }
            }

            //Deserialize done :)
            return result;
        }

        public byte[] ToArray(string des)
        {
            List<byte> data = new List<byte>();
            bool ctn = false;
            for (int i = 0; i < des.Length; i++)
            {
                if (ctn)
                {
                    ctn = !ctn;
                    continue;
                }
                data.Add((byte)int.Parse(des[i].ToString() + des[i+1].ToString(), System.Globalization.NumberStyles.HexNumber));
                if (!ctn) ctn = !ctn;
            }
            return data.ToArray();
        }

        public override String ToString()
        {
            return "Request Count: " + reqCount + "\nRequest/Response: " + response + "\nOpCode: " + opcode + "\nAuthAnswer: "
                + AuthAnswer + "\nTruncation: " + truncation + "\nRec Desired: " + recursion_desired + "\nRec Available: " +
                recursion_available + "\nReturn Code: " + return_code + "\nQuestions: " + question_resource_record_count + "\n"
                + "Answer RR's: " + answer_resource_record_count + "\nAuthority RR's: " + authority_resource_record_count + "\n"
                + "Additional RR's: " + additional_resource_record_count + "\nHostname: " + lookup_hostname + "\nType: " +
                question_type + "\nClass: " + question_class + "\n";
        }

        public enum DnsResourceType : int
        {
            Query = 0,
            Answer = 1,
            Authority = 2,
            Additional = 3,
        }

        //Dns Code references: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10

        public enum DnsResponse : int //All codes
        {
            request = 0,
            response = 1,
        }

        public enum DnsClass : int //All class but not number ranges
        {
            Reserved = 0,
            Internet = 1,
            Chaos = 3,
            Hesiod = 4,
            QClassNone = 254,
            QClassAny = 255,
        }

        public enum DnsType : int //Some of the common types
        {
            A = 1,
            NS = 2,
            CNAME = 5,
            SOA = 6,
            PTR = 12,
            MX = 15,
            AAAA = 28,
        }

        public enum DnsOpCode : int //All assigned opcodes
        {
            Query = 0,
            IQuery = 1,
            Status = 2,
            Notify = 4,
            Update = 5,
        }

        public enum DnsReturnCodes : int //Some of the common return codes
        {
            Success = 0,
            BadFormat = 1,
            ServerFail = 2,
            NonExistentDomain = 3,
            NotImplemented = 4,
            QueryRefused = 5,
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            /*int test = int.Parse("0100", System.Globalization.NumberStyles.HexNumber);
            string str = (test >> 15).ToString();
            Console.WriteLine(str);*/
            Console.WriteLine("Server Created");
            Server s = new Server();
            s.start();
            s.read();
            Console.Read();
        }
    }
}
