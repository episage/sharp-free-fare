using SharpNFC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpFreeFare
{
    public class FreeFareContext : NFCContext, IDisposable
    {
        public FreeFareContext()
            : base()
        {

        }

        public FreeFareDevice ConvertToFreeFareDevice(NFCDevice nfcDevice)
        {
            var ffDev = new FreeFareDevice(nfcDevice.DevicePointer);
            return ffDev;
        }

        public override void Dispose()
        {
            base.Dispose();
        }
    }
}
