using SharpFreeFare.PInvoke;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpFreeFare
{
    public static class Functions
    {
        [DllImport("libfreefare.dll")]
        //MifareTag* freefare_get_tags (nfc_device *device);
        public static extern IntPtr freefare_get_tags(IntPtr device);


        [DllImport("libfreefare.dll")]
        //int mifare_desfire_connect (MifareTag tag)
        public static extern int mifare_desfire_connect(IntPtr tag);

        [DllImport("libfreefare.dll")]
        //int mifare_desfire_select_application (MifareTag tag, MifareDESFireAID aid);
        public static extern int mifare_desfire_select_application(IntPtr tag, IntPtr aid);

        [DllImport("libfreefare.dll")]
        //MifareDESFireAID mifare_desfire_aid_new (uint32_t aid)
        public static extern IntPtr mifare_desfire_aid_new(UInt32 aid);

        [DllImport("libfreefare.dll")]
        //MifareDESFireKey mifare_desfire_3des_key_new (const uint8_t value[16])
        public static extern IntPtr mifare_desfire_3des_key_new([MarshalAs(UnmanagedType.LPArray, SizeConst = 16)] byte[] value);

        [DllImport("libfreefare.dll")]
        //int mifare_desfire_authenticate (MifareTag tag, uint8_t key_no, MifareDESFireKey key)
        public static extern int mifare_desfire_authenticate(IntPtr tag, byte key_no, IntPtr key);

        [DllImport("libfreefare.dll")]
        //ssize_t mifare_desfire_read_data (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data)
        public static extern uint mifare_desfire_read_data(IntPtr tag, byte file_no, int offset, uint length, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)]byte[] data);

        [DllImport("libfreefare.dll")]
        // int mifare_desfire_disconnect (MifareTag tag)
        public static extern int mifare_desfire_disconnect(IntPtr tag);
       
    }
}
