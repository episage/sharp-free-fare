using SharpFreeFare;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace nfc_scan_device
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var ctx = new FreeFareContext())
            {
                string codeBase = Assembly.GetExecutingAssembly().CodeBase;
                string name = Path.GetFileNameWithoutExtension(codeBase);
                Console.WriteLine($"{name} uses libnfc {ctx.Version()}");


                var lst = ctx.ListDeviceNames();
                Console.WriteLine($"{lst.Count} NFC device(s) found:");
                foreach (var d in lst)
                    Console.WriteLine(d);
                Console.ReadKey();
            }
        }
    }
}
