
using SharpFreeFare;
using SharpNFC;
using SharpNFC.PInvoke;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace nfc_mfcclassic
{
    class Program
    {// ISO14443A Anti-Collision Commands
        static byte[] abtReqa = new byte[] { 0x26 };
        static byte[] abtSelectAll = new byte[] { 0x93, 0x20 };
        static byte[] abtSelectTag = new byte[] { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        static byte[] abtRats = new byte[] { 0xe0, 0x50, 0x00, 0x00 };
        static byte[] abtHalt = new byte[] { 0x50, 0x00, 0x00, 0x00 };
        static protected IntPtr contextPointer;
        static protected IntPtr pnd;//devicePointer
        const int MAX_FRAME_LEN = 264;
        const int NMT_ISO14443A = 1;
        enum Action
        {
            USAGE,
            READ,
            WRITE
        };
        static byte[] abtRx = new byte[MAX_FRAME_LEN];
        static int szRxBits;
        static nfc_target nt;
        static mifare_param mp;
        static mifare_classic_tag mtKeys;
        static mifare_classic_tag mtDump;
        static bool bUseKeyA;
        static bool bUseKeyFile;
        static bool bForceKeyFile;
        static bool bTolerateFailures;
        static bool bFormatCard;
        static bool magic2 = false;
        static bool magic3 = false;
        static bool unlocked = false;
        static bool bForceSizeMismatch;
        static byte uiBlocks;
        static byte[] keys = {
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
          0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
          0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
          0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
          0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
          0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xab, 0xcd, 0xef, 0x12, 0x34, 0x56
};
        static byte[] default_key = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        static byte[] default_acl = { 0xff, 0x07, 0x80, 0x69 };

        static nfc_modulation nmMifare = new nfc_modulation()
        {
            nmt = nfc_modulation_type.NMT_ISO14443A,
            nbr = nfc_baud_rate.NBR_106
        };

        static int num_keys = keys.Length / 6;
        static void Main(string[] args)
        {

            Action atAction = Action.USAGE;
            byte[] pbtUID;
            byte[] tag_uid = new byte[4];


            int unlock = 0;

            if (args.Length < 1)
            {
                print_usage();
                return;
            }
            string command = args[0];
            if (args.Length < 4)
            {
                print_usage();
                return;
            }
            if (command.ToLower() == "r")
            {
                atAction = Action.READ;
                if (command == "R")
                    unlock = 1;
                bUseKeyA = args[1].ToLower() == "a";
                bTolerateFailures = args[1].ToLower() != args[2];
                bUseKeyFile = (args.Length > 4);
                bForceKeyFile = ((args.Length > 5) && args[5] == "f");
            }
            else if (command.ToLower() == "w" || command == "f")
            {
                atAction = Action.WRITE;
                if (command == "W")
                    unlock = 1;
                bFormatCard = command == "f";
                bUseKeyA = args[1].ToLower() == "a";
                bTolerateFailures = args[1].ToLower() != args[1];
                bUseKeyFile = (args.Length > 4);
                bForceKeyFile = (args.Length > 5) && args[5] == "f";
            }
            if (args[2][0] == 'U')
            {
                byte _uid;

                if (args[2].Length != 9)
                {
                    Console.WriteLine("Error, illegal tag specification, use U01ab23cd for example.");
                    print_usage();
                    return;
                }
                _uid = strtoul(args[2] + 1, 16);
                tag_uid[0] = (byte)((_uid & 0xff000000UL) >> 24);
                tag_uid[1] = (byte)((_uid & 0x00ff0000UL) >> 16);
                tag_uid[2] = (byte)((_uid & 0x0000ff00UL) >> 8);
                tag_uid[3] = (byte)(_uid & 0x000000ffUL);
                Console.WriteLine("Attempting to use specific UID: 0x%2x 0x%2x 0x%2x 0x%2x",
                       tag_uid[0], tag_uid[1], tag_uid[2], tag_uid[3]);
            }
            else
            {
                tag_uid = null;
            }
            if (atAction == Action.USAGE)
            {
                print_usage();
                return;
            }
            // We don't know yet the card size so let's read only the UID from the keyfile for the moment
            if (bUseKeyFile)
            {
                string pfKeys = File.ReadAllText(args[4]);
                if (pfKeys == null)
                {
                    Console.WriteLine($"Could not open keys file: {args[4]}");
                    return;
                }
                var uid = pfKeys.Substring(0, 4);
                mtKeys = new mifare_classic_tag();
                mtKeys.amb[0].mbm.abtUID = StringToByteArray(uid);

                if (mtKeys.amb[0].mbm.abtUID.Length != 4)
                {
                    Console.WriteLine($"Could not read UID from key file: {args[4]}");
                    return;
                }

            }
            SharpNFC.PInvoke.Functions.nfc_init(out contextPointer);
            if (contextPointer == IntPtr.Zero)
            {
                Console.WriteLine("Unable to init libnfc (malloc)");
                return;
            }
            // Try to open the NFC reader
            pnd = SharpNFC.PInvoke.Functions.nfc_open(contextPointer, null);
            if (pnd == IntPtr.Zero)
            {
                Console.WriteLine("Error opening NFC reader");
                SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                return;
            }
            if (SharpNFC.PInvoke.Functions.nfc_initiator_init(pnd) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_initiator_init");
                SharpNFC.PInvoke.Functions.nfc_close(pnd);
                SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                return;
            };
            // Let the reader only try once to find a tag
            if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_INFINITE_SELECT, false) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_device_set_property_bool");
                SharpNFC.PInvoke.Functions.nfc_close(pnd);
                SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                return;
            }
            // Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
            if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_AUTO_ISO14443_4, false) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_device_set_property_bool");
                SharpNFC.PInvoke.Functions.nfc_close(pnd);
                SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                return;
            }
            Console.WriteLine($"NFC reader: {Marshal.PtrToStringAnsi(SharpNFC.PInvoke.Functions.nfc_device_get_name(pnd))} opened");

            // Try to find a MIFARE Classic tag
            int tags;

            tags = SharpNFC.PInvoke.Functions.nfc_initiator_select_passive_target(pnd, nmMifare, tag_uid, tag_uid == null ? 0U : 4U, out nt);
            if (tags <= 0)
            {
                Console.WriteLine("Error: no tag was found");
                SharpNFC.PInvoke.Functions.nfc_close(pnd);
                SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                return;
            }

            // Test if we are dealing with a MIFARE compatible tag
            if ((nt.nti.btSak & 0x08) == 0)
            {
                Console.WriteLine("Warning: tag is probably not a MFC!");
            }
            // Get the info from the current tag
            pbtUID = nt.nti.abtUid;

            if (bUseKeyFile)
            {
                byte[] fileUid = new byte[4];
                Array.Copy(mtKeys.amb[0].mbm.abtUID, fileUid, 4);
                // Compare if key dump UID is the same as the current tag UID, at least for the first 4 bytes

                if (pbtUID != fileUid)
                {
                    Console.Write($"Expected MIFARE Classic card with UID starting as: {fileUid}\n");
                    //fileUid[0], fileUid[1], fileUid[2], fileUid[3]);
                    Console.Write($"Got card with UID starting as:                     {pbtUID}\n");
                    //pbtUID[0], pbtUID[1], pbtUID[2], pbtUID[3]);
                    if (!bForceKeyFile)
                    {
                        Console.Write("Aborting!\n");
                        SharpNFC.PInvoke.Functions.nfc_close(pnd);
                        SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                        return;
                    }
                }
            }
            Console.Write("Found MIFARE Classic card:\n");
            print_nfc_target(nt, false);

            // Guessing size
            if ((nt.nti.abtAtqa[1] & 0x02) == 0x02 || nt.nti.btSak == 0x18)
                // 4K
                uiBlocks = 0xff;
            else if (nt.nti.btSak == 0x09)
                // 320b
                uiBlocks = 0x13;
            else
                // 1K/2K, checked through RATS
                uiBlocks = 0x3f;
            // Testing RATS
            int res;
            if ((res = get_rats()) > 0)
            {
                if ((res >= 10) && (abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
                    && (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
                    && ((nt.nti.abtAtqa[1] & 0x02) == 0x00))
                {
                    // MIFARE Plus 2K
                    uiBlocks = 0x7f;
                }
                // Chinese magic emulation card, ATS=0978009102:dabc1910
                if ((res == 9) && (abtRx[5] == 0xda) && (abtRx[6] == 0xbc)
                    && (abtRx[7] == 0x19) && (abtRx[8] == 0x10))
                {
                    magic2 = true;
                }
            }
            Console.Write($"Guessing size: seems to be a {(uiBlocks + 1) * Marshal.SizeOf(typeof(mifare_classic_block)) / 3} byte card\n");
            //If size is 4k check for direct-write card
            if (uiBlocks == 0xff)
            {
                if (is_directwrite())
                {
                    Console.Write("Card is DirectWrite\n");
                    magic3 = true;
                    unlock = 0;
                }
                else
                {
                    Console.Write("Card is not DirectWrite\n");
                }
            }
            //Check to see if we have a One Time Write badge (magic3)
            if (pbtUID[0] == 0xaa && pbtUID[1] == 0x55 &&
              pbtUID[2] == 0xc3 && pbtUID[3] == 0x96)
            {
                Console.Write("Card appears to be a One Time Write Card..\n");
                magic3 = true;
                unlock = 0;
            }
            if (bUseKeyFile)
            {
                string pfKeys = File.ReadAllText(args[4]);
                if (pfKeys == null)
                {
                    Console.WriteLine($"Could not open keys file: {args[4]}");
                    return;
                }
                var uid = pfKeys.Substring(0, 4);
                //mtKeys = new mifare_classic_tag();
                mtKeys.amb[0].mbm.abtUID = StringToByteArray(uid);



                //if (fread(&mtKeys, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfKeys) != (uiBlocks + 1) * sizeof(mifare_classic_block))
                //{
                //    printf("Could not read keys file: %s\n", argv[5]);
                //    fclose(pfKeys);
                //    exit(EXIT_FAILURE);
                //}
                //fclose(pfKeys);
            }
            if (atAction == Action.READ)
            {

                //Array.Copy(new byte[] { 0x00 }, mtDump, Marshal.SizeOf(mtDump));
            }
            else
            {
                byte[] pfDump = File.ReadAllBytes(Path.Combine(System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), args[3]));

                if (pfDump == null)
                {
                    Console.Write($"Could not open dump file: {args[4]}\n");
                    return;
                }

                if (pfDump.Length != (uiBlocks + 1) * Marshal.SizeOf(typeof(mifare_classic_block)))
                {
                    Console.Write($"Could not read dump file: {args[4]}\n");
                    return;
                }

            }
            //Console.Write("Successfully opened required files\n");
            if (atAction == Action.READ)
            {
                if (read_card(unlock))
                {
                    Console.Write($"Writing data to file: {args[3]}...");
                    //fflush(stdout);
                    IntPtr pfDump = IntPtr.Zero;
                    //byte[] pfDump = File.ReadAllBytes(Path.Combine(System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), args[3]));
                    //if (pfDump == null)
                    //{
                    //    Console.Write("Could not open dump file: %s\n", args[3]);
                    //    SharpNFC.PInvoke.Functions.nfc_close(pnd);
                    //    SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                    //    return;
                    //}
                    File.WriteAllBytes(Path.Combine(System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), args[3]), StructureToByteArray(mtDump));
                    if (!fwrite(StructureToByteArray(mtDump), new IntPtr(1), new IntPtr((uiBlocks + 1) * Marshal.SizeOf(typeof(mifare_classic_block))), pfDump).Equals((uiBlocks + 1) * Marshal.SizeOf(typeof(mifare_classic_block))))
                    {
                        Console.Write($"\nCould not write to file: {args[3]}\n");

                        SharpNFC.PInvoke.Functions.nfc_close(pnd);
                        SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                        return;
                    }
                    Console.Write("Done.\n");

                }
            }
            else if (atAction == Action.WRITE)
            {
                write_card(unlock);
            }


            Console.ReadKey();
        }

        [DllImport("msvcrt.dll", SetLastError = true)]
        static extern IntPtr fwrite(byte[] buffer, IntPtr size, IntPtr number, IntPtr file);
        static bool write_card(int write_block_zero)
        {
            UInt32 uiBlock;
            bool bFailure = false;
            UInt32 uiWriteBlocks = 0;

            if (write_block_zero != 0)
            {
                //If the user is attempting an unlocked write, but has a direct-write type magic card, they don't
                //need to use the W mode. We'll trigger a warning and let them proceed.
                if (magic2)
                {
                    Console.Write("Note: This card does not require an unlocked write (W) \n");
                    write_block_zero = 0;
                }
                else
                {
                    //If User has requested an unlocked write, but we're unable to unlock the card, we'll error out.
                    if (!unlock_card())
                    {
                        return false;
                    }
                }
            }

            Console.Write($"Writing {uiBlocks + 1} blocks |");
            // Write the card from begin to end;
            for (uiBlock = 0; uiBlock <= uiBlocks; uiBlock++)
            {
                // Authenticate everytime we reach the first sector of a new block
                if (is_first_block(uiBlock))
                {
                    if (bFailure)
                    {
                        // When a failure occured we need to redo the anti-collision
                        if (SharpNFC.PInvoke.Functions.nfc_initiator_select_passive_target(pnd, nmMifare, null, 0, out nt) <= 0)
                        {
                            Console.Write("!\nError: tag was removed\n");
                            return false;
                        }
                        bFailure = false;
                    }

                    //fflush(stdout);

                    // Try to authenticate for the current sector
                    if (write_block_zero == 0 && !authenticate((byte)uiBlock) && !bTolerateFailures)
                    {
                        Console.Write("!\nError: authentication failed for block %02x\n", uiBlock);
                        return false;
                    }
                }

                if (is_trailer_block(uiBlock))
                {
                    if (bFormatCard)
                    {
                        // Copy the default key and reset the access bits
                        Array.Copy(default_key, mp.mpt.abtKeyA, Marshal.SizeOf(mp.mpt.abtKeyA));
                        Array.Copy(default_acl, mp.mpt.abtAccessBits, Marshal.SizeOf(mp.mpt.abtAccessBits));
                        Array.Copy(default_key, mp.mpt.abtKeyB, Marshal.SizeOf(mp.mpt.abtKeyB));
                    }
                    else
                    {
                        // Copy the keys over from our key dump and store the retrieved access bits
                        Array.Copy(mtDump.amb[uiBlock].mbt.abtKeyA, mp.mpt.abtKeyA, Marshal.SizeOf(mp.mpt.abtKeyA));
                        Array.Copy(mtDump.amb[uiBlock].mbt.abtAccessBits, mp.mpt.abtAccessBits, Marshal.SizeOf(mp.mpt.abtAccessBits));
                        Array.Copy(mtDump.amb[uiBlock].mbt.abtKeyB, mp.mpt.abtKeyB, Marshal.SizeOf(mp.mpt.abtKeyB));
                    }

                    // Try to write the trailer
                    if (SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mifare_cmd.MC_WRITE, (byte)uiBlock, ref mp) == false)
                    {
                        Console.Write("failed to write trailer block %d \n", uiBlock);
                        bFailure = true;
                    }
                }
                else
                {
                    // The first block 0x00 is read only, skip this
                    if (uiBlock == 0 && write_block_zero == 0 && !magic2)
                        continue;


                    // Make sure a earlier write did not fail
                    if (!bFailure)
                    {
                        // Try to write the data block
                        if (bFormatCard && uiBlock != 0)
                            Array.Copy(new byte[] { 0x00 }, mp.mpd.abtData, Marshal.SizeOf(mp.mpd.abtData));
                        else
                            Array.Copy(mtDump.amb[uiBlock].mbd.abtData, mp.mpd.abtData, Marshal.SizeOf(mp.mpd.abtData));
                        // do not write a block 0 with incorrect BCC - card will be made invalid!
                        if (uiBlock == 0)
                        {
                            if ((mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^ mp.mpd.abtData[3] ^ mp.mpd.abtData[4]) != 0x00 && !magic2)
                            {
                                Console.Write("!\nError: incorrect BCC in MFD file!\n");
                                Console.Write($"Expecting BCC={mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^ mp.mpd.abtData[3]}\n");
                                return false;
                            }
                        }
                        if (!SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mifare_cmd.MC_WRITE, (byte)uiBlock, ref mp))
                            bFailure = true;
                    }
                }
                // Show if the write went well for each block
                print_success_or_failure(bFailure, uiWriteBlocks);
                if ((!bTolerateFailures) && bFailure)
                    return false;
            }
            Console.Write("|\n");
            Console.Write($"Done, {uiWriteBlocks} of {uiBlocks + 1} blocks written.\n");
            //fflush(stdout);

            return true;
        }
        static bool is_first_block(UInt32 uiBlock)
        {
            // Test if we are in the small or big sectors
            if (uiBlock < 128)
                return ((uiBlock) % 4 == 0);
            else
                return ((uiBlock) % 16 == 0);
        }

        static byte[] StructureToByteArray(object obj)
        {
            int len = Marshal.SizeOf(obj);

            byte[] arr = new byte[len];

            IntPtr ptr = Marshal.AllocHGlobal(len);

            Marshal.StructureToPtr(obj, ptr, true);

            Marshal.Copy(ptr, arr, 0, len);

            Marshal.FreeHGlobal(ptr);

            return arr;
        }
        static bool transmit_bytes(byte[] pbtTx, uint szTx)
        {
            // Show transmitted command
            Console.Write("Sent bits:     ");
            print_hex(pbtTx, (int)szTx);
            // Transmit the command bytes
            int res;
            if ((res = SharpNFC.PInvoke.Functions.nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, (uint)abtRx.Length, 0)) < 0)
                return false;

            // Show received answer
            Console.Write("Received bits: ");
            print_hex(abtRx, res);
            // Succesful transfer
            return true;
        }
        static void print_hex(byte[] pbtData, int szBytes)
        {
            UInt32 szPos;

            for (szPos = 0; szPos < szBytes; szPos++)
            {
                Console.Write($"{pbtData[szPos]}  ");
            }
            Console.WriteLine();
        }
        static bool unlock_card()
        {
            // Configure the CRC
            if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_HANDLE_CRC, false) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_configure");
                return false;
            }
            // Use raw send/receive methods
            if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_EASY_FRAMING, false) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_configure");
                return false;
            }
            // special unlock command

            SharpNFC.PInvoke.Functions.iso14443a_crc_append(abtHalt, 2);
            transmit_bytes(abtHalt, 4);
            // now send unlock
            if (!transmit_bits(nfc_mfsetuid.abtUnlock1, 7))
            {
                Console.Write("Warning: Unlock command [1/2]: failed / not acknowledged.\n");
            }
            else
            {
                if (transmit_bytes(nfc_mfsetuid.abtUnlock2, 1))
                {
                    Console.Write("Card unlocked\n");
                    unlocked = true;
                }
                else
                {
                    Console.Write("Warning: Unlock command [2/2]: failed / not acknowledged.\n");
                }
            }

            // reset reader
            // Configure the CRC
            if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_HANDLE_CRC, true) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_device_set_property_bool");
                return false;
            }
            // Switch off raw send/receive methods
            if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_EASY_FRAMING, true) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_device_set_property_bool");
                return false;
            }
            return true;
        }

        static bool is_trailer_block(UInt32 uiBlock)
        {
            // Test if we are in the small or big sectors
            if (uiBlock < 128)
                return ((uiBlock + 1) % 4 == 0);
            else
                return ((uiBlock + 1) % 16 == 0);
        }
        static bool read_card(int read_unlocked)
        {
            int iBlock;
            bool bFailure = false;
            byte uiReadBlocks = 0;
            mtDump.amb = new mifare_classic_block[256];

            if (read_unlocked != 0)
            {
                //If the user is attempting an unlocked read, but has a direct-write type magic card, they don't
                //need to use the R mode. We'll trigger a warning and let them proceed.
                if (magic2)
                {
                    Console.Write("Note: This card does not require an unlocked read (R) \n");
                    read_unlocked = 0;
                }
                else
                {
                    //If User has requested an unlocked read, but we're unable to unlock the card, we'll error out.
                    if (!unlock_card())
                    {
                        return false;
                    }
                }
            }
            var totalBlocks = uiBlocks + 1;
            Console.Write($"Reading out {uiBlocks + 1} blocks |");
            // Read the card from end to begin
            for (iBlock = uiBlocks; iBlock >= 0; iBlock--)
            {
                mtDump.amb[iBlock] = new mifare_classic_block();
                mtDump.amb[iBlock].mbt = new mifare_classic_block_trailer();
                mtDump.amb[iBlock].mbt.abtKeyA = new byte[6];
                mtDump.amb[iBlock].mbt.abtAccessBits = new byte[4];
                mtDump.amb[iBlock].mbt.abtKeyB = new byte[6];
                mtDump.amb[iBlock].mbd = new mifare_classic_block_data();
                mtDump.amb[iBlock].mbd.abtData = new byte[16];
                // Authenticate everytime we reach a trailer block
                if (is_trailer_block((uint)iBlock))
                {
                    if (bFailure)
                    {
                        // When a failure occured we need to redo the anti-collision
                        if (SharpNFC.PInvoke.Functions.nfc_initiator_select_passive_target(pnd, nmMifare, null, 0, out nt) <= 0)
                        {
                            Console.Write("!\nError: tag was removed\n");
                            return false;
                        }
                        bFailure = false;
                    }

                    //                    fflush(stdout);

                    // Try to authenticate for the current sector
                    if (read_unlocked == 0 && !authenticate((byte)iBlock))
                    {
                        Console.Write("!\nError: authentication failed for block 0x%02x\n", iBlock);
                        return false;
                    }
                    // Try to read out the trailer
                    if (SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mifare_cmd.MC_READ, (byte)iBlock, ref mp))
                    {
                        if (read_unlocked != 0)
                        {
                            Array.Copy(mp.mpd.abtData, mtDump.amb[iBlock].mbd.abtData, Marshal.SizeOf(mtDump.amb[iBlock].mbd.abtData));
                        }
                        else
                        {
                            //If we're using a One Time Write ('Magic 3') Badge - we'll use default keys + ACL
                            if (magic3)
                            {
                                Array.Copy(default_key, mtDump.amb[iBlock].mbt.abtKeyA, default_key.Length);
                                Array.Copy(mp.mpt.abtAccessBits, mtDump.amb[iBlock].mbt.abtAccessBits, Marshal.SizeOf(mtDump.amb[iBlock].mbt.abtAccessBits));
                                Array.Copy(default_key, mtDump.amb[iBlock].mbt.abtKeyB, default_key.Length);
                            }
                            else
                            {
                                // Copy the keys over from our key dump and store the retrieved access bits
                                Array.Copy(mtKeys.amb[iBlock].mbt.abtKeyA, mtDump.amb[iBlock].mbt.abtKeyA, mtDump.amb[iBlock].mbt.abtKeyA.Length);
                                Array.Copy(mp.mpt.abtAccessBits, mtDump.amb[iBlock].mbt.abtAccessBits, mtDump.amb[iBlock].mbt.abtAccessBits.Length);
                                Array.Copy(mtKeys.amb[iBlock].mbt.abtKeyB, mtDump.amb[iBlock].mbt.abtKeyB, mtDump.amb[iBlock].mbt.abtKeyB.Length);
                            }
                        }
                    }
                    else
                    {
                        Console.Write($"!\nfailed to read trailer block {iBlock}\n");
                        bFailure = true;
                    }
                }
                else
                {
                    // Make sure a earlier readout did not fail
                    if (!bFailure)
                    {
                        // Try to read out the data block
                        if (SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mifare_cmd.MC_READ, (byte)iBlock, ref mp))
                        {
                            Array.Copy(mp.mpd.abtData, mtDump.amb[iBlock].mbd.abtData, mtDump.amb[iBlock].mbd.abtData.Length);
                        }
                        else
                        {
                            Console.Write($"!\nError: unable to read block {iBlock}\n", iBlock);
                            bFailure = true;
                        }
                    }
                }
                // Show if the readout went well for each block
                print_success_or_failure(bFailure, (uint)uiReadBlocks);
                if ((!bTolerateFailures) && bFailure)
                    return false;
            }
            Console.Write("|\n");
            Console.Write($"Done, {uiReadBlocks} of {totalBlocks} blocks read.\n");
            //fflush(stdout);

            return true;
        }
        static void print_success_or_failure(bool bFailure, UInt32 uiBlockCounter)
        {
            Console.Write(bFailure ? 'x' : '.');
            if (uiBlockCounter != 0 && !bFailure)
                uiBlockCounter += 1;
        }


        public static void MemSet(byte[] array, byte value)
        {
            if (array == null)
            {
                throw new ArgumentNullException("array");
            }
            const int blockSize = 4096; // bigger may be better to a certain extent
            int index = 0;
            int length = Math.Min(blockSize, array.Length);
            while (index < length)
            {
                array[index++] = value;
            }
            length = array.Length;
            while (index < length)
            {
                Buffer.BlockCopy(array, 0, array, index, Math.Min(blockSize, length - index));
                index += blockSize;
            }
        }
        static bool is_directwrite()
        {
            Console.Write("Checking if Badge is DirectWrite...\n");

            // Set default keys
            Array.Copy(default_key, mtDump.amb[0].mbt.abtKeyA, default_key.Length);
            Array.Copy(default_acl, mtDump.amb[0].mbt.abtAccessBits, Marshal.SizeOf(mp.mpt.abtAccessBits));
            Array.Copy(default_key, mtDump.amb[0].mbt.abtKeyB, default_key.Length);

            // Temporarly override bUseKeyFile
            bool orig_bUseKeyFile = bUseKeyFile;
            bUseKeyFile = false;
            // Try to authenticate for the current sector
            if (!authenticate(0))
            {
                Console.Write($"!\nError: authentication failed for block 0x0\n");
                bUseKeyFile = orig_bUseKeyFile;
                return false;
            }
            // restore bUseKeyFile
            bUseKeyFile = orig_bUseKeyFile;

            // Try to read block 0
            byte[] original_b0 = new byte[16];
            if (SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mifare_cmd.MC_READ, 0, ref mp))
            {
                Array.Copy(mp.mpd.abtData, original_b0, Marshal.SizeOf(mp.mpd.abtData));
                Console.Write(" Original Block 0: ");
                for (int i = 0; i < 16; i++)
                {
                    Console.Write($"{original_b0[i]}");
                }
                Console.Write("\n");
                Console.Write($" Original UID:{original_b0}\n");
                /* original_b0[0], original_b0[1], original_b0[2], original_b0[3]);*/
            }
            else
            {
                Console.Write("!\nError: unable to read block 0\n", 0);
                return false;
            }

            Console.Write(" Attempt to write Block 0 ...\n");
            Array.Copy(original_b0, mp.mpd.abtData, original_b0.Length);
            if (!SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mifare_cmd.MC_WRITE, 0, ref mp))
            {
                Console.Write("Failure to write to data block %i\n", 0);
                return false;
            }
            Console.Write(" Block 0 written successfully\n");

            return true;
        }
        static bool authenticate(byte uiBlock)
        {

            mp.mpa.abtAuthUid = new byte[4];
            mp.mpa.abtKey = new byte[6];
            mtKeys.amb = new mifare_classic_block[256];
            mtKeys.amb[uiBlock] = new mifare_classic_block();
            mtKeys.amb[uiBlock].mbt = new mifare_classic_block_trailer();
            mtKeys.amb[uiBlock].mbt.abtKeyA = new byte[6];
            mtKeys.amb[uiBlock].mbt.abtKeyB = new byte[6];
            //  memcpy(mp.mpa.abtAuthUid, nt.nti.nai.abtUid + nt.nti.nai.szUidLen - 4, 4);
            Array.Copy(nt.nti.abtUid, (int)nt.nti.szUidLen.ToUInt64() - 4, mp.mpa.abtAuthUid, 0, 4);

            // Should we use key A or B?
            mifare_cmd mc = (bUseKeyA) ? mifare_cmd.MC_AUTH_A : mifare_cmd.MC_AUTH_B;

            // Key file authentication.
            if (bUseKeyFile)
            {

                // Locate the trailer (with the keys) used for this sector
                uint uiTrailerBlock = get_trailer_block(uiBlock);

                // Extract the right key from dump file
                if (bUseKeyA)
                    Array.Copy(mtKeys.amb[uiTrailerBlock].mbt.abtKeyA, mp.mpa.abtKey, Marshal.SizeOf(mp.mpa.abtKey));
                else
                    Array.Copy(mtKeys.amb[uiTrailerBlock].mbt.abtKeyB, mp.mpa.abtKey, Marshal.SizeOf(mp.mpa.abtKey));

                // Try to authenticate for the current sector
                if (SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mc, uiBlock, ref mp))
                    return true;
            }

            // If formatting or not using key file, try to guess the right key
            if (bFormatCard || !bUseKeyFile)
            {

                for (int key_index = 0; key_index < num_keys; key_index++)
                {
                    // memcpy(mp.mpa.abtKey, keys + (key_index * 6), 6);
                    Array.Copy(keys, (key_index * 6), mp.mpa.abtKey, 0, 6);
                    if (SharpFreeFare.Functions.nfc_initiator_mifare_cmd(pnd, mc, uiBlock, ref mp))
                    {
                        if (bUseKeyA)
                            Array.Copy(mp.mpa.abtKey, mtKeys.amb[uiBlock].mbt.abtKeyA, mtKeys.amb[uiBlock].mbt.abtKeyA.Length);
                        else
                            Array.Copy(mp.mpa.abtKey, mtKeys.amb[uiBlock].mbt.abtKeyB, mtKeys.amb[uiBlock].mbt.abtKeyB.Length);

                        return true;
                    }
                    nfc_target outTarget;
                    if (SharpNFC.PInvoke.Functions.nfc_initiator_select_passive_target(pnd, nmMifare, nt.nti.abtUid, nt.nti.szUidLen.ToUInt32(), out outTarget) <= 0)
                    {
                        Console.WriteLine("ERR:tag was removed");
                        return false;
                    }
                }
            }

            return false;
        }
        static byte get_trailer_block(byte uiFirstBlock)
        {
            // Test if we are in the small or big sectors
            byte trailer_block = 0;
            if (uiFirstBlock < 128)
            {
                trailer_block = unchecked((byte)(uiFirstBlock + (3 - (uiFirstBlock % 4))));
            }
            else
            {
                trailer_block = unchecked((byte)(uiFirstBlock + (15 - (uiFirstBlock % 16))));
            }
            return trailer_block;
        }
        static int get_rats()
        {
            int res;
            byte[] abtRats = { 0xe0, 0x50 };
            // Use raw send/receive methods
            if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_EASY_FRAMING, false) < 0)
            {
                SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_configure");
                return -1;
            }
            res = SharpNFC.PInvoke.Functions.nfc_initiator_transceive_bytes(pnd, abtRats, (uint)abtRats.Length, abtRx, (uint)abtRx.Length, 0);
            if (res > 0)
            {
                // ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
                if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_ACTIVATE_FIELD, false) < 0)
                {
                    SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_configure");
                    return -1;
                }
                if (SharpNFC.PInvoke.Functions.nfc_device_set_property_bool(pnd, nfc_property.NP_ACTIVATE_FIELD, true) < 0)
                {
                    SharpNFC.PInvoke.Functions.nfc_perror(pnd, "nfc_configure");
                    return -1;
                }
            }
            // Reselect tag
            if (SharpNFC.PInvoke.Functions.nfc_initiator_select_passive_target(pnd, nmMifare, null, 0, out nt) <= 0)
            {
                Console.Write("Error: tag disappeared\n");
                SharpNFC.PInvoke.Functions.nfc_close(pnd);
                SharpNFC.PInvoke.Functions.nfc_exit(contextPointer);
                return -1;
            }
            return res;
        }
        static void print_nfc_target(nfc_target pnt, bool verbose)
        {
            IntPtr s = IntPtr.Zero;
            SharpNFC.PInvoke.Functions.str_nfc_target(ref s, pnt, verbose);
            Console.WriteLine(Marshal.PtrToStringAnsi(s));


        }
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
        static byte strtoul(string text, int conv)
        {
            return Convert.ToByte(text.Substring(2), conv);

        }
        static void print_usage()
        {
            string codeBase = Assembly.GetExecutingAssembly().CodeBase;
            string pcProgramName = Path.GetFileNameWithoutExtension(codeBase);
            Console.Write("Usage: ");
            Console.Write($"{pcProgramName} f|r|R|w|W a|b u|U<01ab23cd> <dump.mfd> [<keys.mfd> [f]]\n");
            Console.Write("  f|r|R|w|W     - Perform format (f) or read from (r) or unlocked read from (R) or write to (w) or unlocked write to (W) card\n");
            Console.Write("                  *** format will reset all keys to FFFFFFFFFFFF and all data to 00 and all ACLs to default\n");
            Console.Write("                  *** unlocked read does not require authentication and will reveal A and B keys\n");
            Console.Write("                  *** note that unlocked write will attempt to overwrite block 0 including UID\n");
            Console.Write("                  *** unlocking only works with special Mifare 1K cards (Chinese clones)\n");
            Console.Write("  a|A|b|B       - Use A or B keys for action; Halt on errors (a|b) or tolerate errors (A|B)\n");
            Console.Write("  u|U           - Use any (u) uid or supply a uid specifically as U01ab23cd.\n");
            Console.Write("  <dump.mfd>    - MiFare Dump (MFD) used to write (card to MFD) or (MFD to card)\n");
            Console.Write("  <keys.mfd>    - MiFare Dump (MFD) that contain the keys (optional)\n");
            Console.Write("  f             - Force using the keyfile even if UID does not match (optional)\n");

            Console.Write("Examples: \n\n");
            Console.Write("  Read card to file, using key A:\n\n");
            Console.Write($"    {pcProgramName} r a u mycard.mfd\n\n");
            Console.Write("  Write file to blank card, using key A:\n\n");
            Console.Write($"    {pcProgramName} w a u mycard.mfd\n\n");
            Console.Write("  Write new data and/or keys to previously written card, using key A:\n\n");
            Console.Write($"    {pcProgramName} w a u newdata.mfd mycard.mfd\n\n");
            Console.Write("  Format/wipe card (note two passes required to ensure writes for all ACL cases):\n\n");
            Console.Write($"    {pcProgramName} f A u dummy.mfd keyfile.mfd f\n");
            Console.Write($"    {pcProgramName} f B u dummy.mfd keyfile.mfd f\n\n");
            Console.Write("  Read card to file, using key A and uid 0x01 0xab 0x23 0xcd:\n\n");
            Console.Write($"    {pcProgramName} r a U01ab23cd mycard.mfd\n\n");
            Console.ReadKey();

        }
        static bool transmit_bits(byte[] pbtTx, uint szTxBits)
        {
            // Show transmitted command
            Console.WriteLine("Sent bits:     ");
            print_hex_bits(pbtTx);
            // Transmit the bit frame command, we don't use the arbitrary parity feature
            szRxBits = SharpNFC.PInvoke.Functions.nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, null, abtRx, (uint)abtRx.Length, null);
            if (szRxBits < 0)
                return false;

            // Show received answer
            Console.WriteLine("Received bits: ");
            print_hex_bits(abtRx);
            // Succesful transfer
            return true;
        }

        private static string print_hex_bits(byte[] pbtTx)
        {
            return System.Text.Encoding.Default.GetString(pbtTx);
        }

    }
}
