using SharpFreeFare.PInvoke;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpFreeFare
{
    public class MifareTag : IDisposable
    {
        public IntPtr TagPointer;

        internal MifareTag(IntPtr mifare_tag)
        {
            this.TagPointer = mifare_tag;
        }

        public mifare_tag GetStructure()
        {
            return (mifare_tag)Marshal.PtrToStructure(TagPointer, typeof(mifare_tag));
        }

        public void Connect()
        {
            var result = Functions.mifare_desfire_connect(TagPointer);

            if (result < 0)
            {
                throw new Exception("Can't connect to Mifare DESFire target.");
            }
        }

        public void SelectApplication(uint applicationId)
        {
            var aidPtr = Functions.mifare_desfire_aid_new(applicationId);

            var result = Functions.mifare_desfire_select_application(TagPointer, aidPtr);

            if (result < 0)
            {
                throw new Exception("mifare_desfire_select_application failed.");
            }
        }

        public bool Authenticate(byte keyNumber, byte[] key)
        {
            IntPtr keyPtr = Functions.mifare_desfire_3des_key_new(key);

            var result = Functions.mifare_desfire_authenticate(TagPointer, keyNumber, keyPtr);

            if (result < 0)
            {
                return false;
            }

            return true;
        }

        public byte[] ReadData(byte fileID, int startOffset, uint length)
        {
            byte[] data = new byte[length];
            Functions.mifare_desfire_read_data(TagPointer, fileID, startOffset, length, data);

            return data;
        }

        public void Dispose()
        {
            Functions.mifare_desfire_disconnect(TagPointer);
        }
    }
}
