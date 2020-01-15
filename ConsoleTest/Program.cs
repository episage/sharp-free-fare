using SharpFreeFare;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleTest
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
                var device = ctx.OpenDevice(lst.First());
                var ffd = ctx.ConvertToFreeFareDevice(device);
                var tags = ffd.GetTags();
                foreach (var t in tags)
                {
                    Console.WriteLine(t.GetStructure().tag_info);
                }
                Console.ReadKey();
            }
        }
    }
}
