using SharpNFC.PInvoke;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpFreeFare.PInvoke
{
    /*
     * This structure is common to all supported MIFARE targets but shall not be
     * used directly (it's some kind of abstract class).  All members in this
     * structure are initialized by freefare_get_tags().
     *
     * Extra members in derived classes are initialized in the correpsonding
     * mifare_*_connect() function.
     */
    [StructLayout(LayoutKind.Sequential)]
    public struct mifare_tag
    {
        public IntPtr device;
        public nfc_iso14443a_info info;
        public IntPtr tag_info;
        public int active;
    };

    ///*
    // * This structure is common to all supported MIFARE targets but shall not be
    // * used directly (it's some kind of abstract class).  All members in this
    // * structure are initialized by freefare_get_tags().
    // *
    // * Extra members in derived classes are initialized in the correpsonding
    // * mifare_*_connect() function.
    // */
    //struct mifare_tag {
    //    nfc_device *device;
    //    nfc_iso14443a_info info;
    //    const struct supported_tag *tag_info;
    //    int active;
    //};
}
