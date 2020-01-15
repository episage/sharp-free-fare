using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpNFC.PInvoke
{
    public class nfc_mfsetuid
    {
        // special unlock command
        public static byte[] abtUnlock1 = new byte[] { 0x40 };
        public static byte[] abtUnlock2 = new byte[] { 0x43 };
        public static byte abtWipe = 0x41;
        public static byte[] abtWrite = new byte[4] { 0xa0, 0x00, 0x5f, 0xb1 };
        public static byte[] abtData = new byte[18] { 0x01, 0x23, 0x45, 0x67, 0x00, 0x08, 0x04, 0x00, 0x46, 0x59, 0x25, 0x58, 0x49, 0x10, 0x23, 0x02, 0x23, 0xeb };
        public static byte[] abtBlank = new byte[18] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x36, 0xCC };
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct mifare_classic_tag
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public mifare_classic_block[] amb ;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct mifare_classic_block
    {
        public mifare_classic_block_manufacturer mbm;
        public mifare_classic_block_data mbd;
        public mifare_classic_block_trailer mbt;
    }
    [StructLayout(LayoutKind.Sequential)]
    // MIFARE Classic
    public struct mifare_classic_block_manufacturer
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] abtUID;  // beware for 7bytes UID it goes over next fields
        public byte btBCC;
        public byte btSAK;      // beware it's not always exactly SAK
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] abtATQA;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] abtManufacturer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct mifare_classic_block_data
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] abtData;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct mifare_classic_block_trailer
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] abtKeyA;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] abtAccessBits;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] abtKeyB;
    }
    public enum mifare_cmd
    {
        MC_AUTH_A = 0x60,
        MC_AUTH_B = 0x61,
        MC_READ = 0x30,
        MC_WRITE = 0xA0,
        MC_TRANSFER = 0xB0,
        MC_DECREMENT = 0xC0,
        MC_INCREMENT = 0xC1,
        MC_STORE = 0xC2
    };


    // MIFARE command params
    public struct mifare_param_auth
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] abtKey;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] abtAuthUid;
    };

    public struct mifare_param_data
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] abtData;
    };

    public struct mifare_param_value
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] abtValue;
    };

    public struct mifare_param_trailer
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] abtKeyA;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] abtAccessBits;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] abtKeyB;
    }

    public struct mifare_param
    {
        public mifare_param_auth mpa;
        public mifare_param_data mpd;
        public mifare_param_value mpv;
        public mifare_param_trailer mpt;
    }



}
