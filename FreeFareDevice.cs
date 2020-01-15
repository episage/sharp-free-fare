using SharpNFC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpFreeFare
{
    public class FreeFareDevice : NFCDevice //musi dziedziczyc po nfcDevice bo to jest nfcDevice tylko ze rozszezone
    {
        protected internal FreeFareDevice(IntPtr devicePointer)
            : base(devicePointer)
        {

        }

       public List<MifareTag> GetTags()
        {
            IntPtr unmanaged_mifare_tag_array_pointer;
            try
            {
                unmanaged_mifare_tag_array_pointer = Functions.freefare_get_tags(base.DevicePointer);

                if (unmanaged_mifare_tag_array_pointer == IntPtr.Zero)
                {
                    throw new Exception();
                }
            }
            catch (Exception)
            {
                throw new Exception("freefare_get_tags failed.");
            }

            var mifareTags = new List<MifareTag>();
            for (int i = 0; ; i++)
            {
                IntPtr tagPtr = (IntPtr)Marshal.PtrToStructure(unmanaged_mifare_tag_array_pointer + i * Marshal.SizeOf(unmanaged_mifare_tag_array_pointer), typeof(IntPtr));
                if (tagPtr == IntPtr.Zero)
                {
                    break;
                }

                mifareTags.Add(new MifareTag(tagPtr));
            }

            return mifareTags;
        }
    }
}
