using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using Microsoft.Phone.Controls;
using Microsoft.Phone.Shell;
using NFC_Analyzer.Resources;
using Windows.Networking.Proximity;
using Windows.Storage.Streams;

namespace NFC_Analyzer
{
    public partial class MainPage : PhoneApplicationPage
    {
        //private Model Game;
        private App currentApp;

        // Constructor
        public MainPage()
        {
            try
            {
                InitializeComponent();
            }
            catch
            {
            }
            currentApp = (App)Application.Current;

            initProximity();
        }

        public bool initProximity()
        {
            string proxString = "*** ";

            // Initialize the Proximity Device.
            currentApp.proximityDevice = ProximityDevice.GetDefault();

            // Make sure NFC is supported
            if (currentApp.proximityDevice != null)
            {
               proxString += AppResources.ProxDevInit + " ***\n";

                currentApp.proximityDevice.DeviceArrived += proximityDeviceArrived;
                currentApp.proximityDevice.DeviceDeparted += proximityDeviceDeparted;

                try
                {
                    currentApp.IdWindowsUri = currentApp.proximityDevice.SubscribeForMessage("WindowsUri", messageReceived);
                   proxString += AppResources.MsgTypeHdr + " \"WindowsUri\" " + AppResources.subscribed + "\n";
                }
                catch
                {
                   proxString += AppResources.MsgTypeHdr + " \"WindowsUri\" " + AppResources.rejected + "\n";
                }

                try
                {
                    currentApp.IdWindowsMime = currentApp.proximityDevice.SubscribeForMessage("WindowsMime", messageReceived);
                   proxString += AppResources.MsgTypeHdr + " \"WindowsMime\" " + AppResources.subscribed + "\n";
                }
                catch
                {
                   proxString += AppResources.MsgTypeHdr + " \"WindowsMime\" " + AppResources.rejected + "\n";
                }

                try
                {
                    currentApp.IdWriteableTag = currentApp.proximityDevice.SubscribeForMessage("WriteableTag", writeableTagReceived);
                   proxString += AppResources.MsgTypeHdr + " \"WriteableTag\" " + AppResources.subscribed + "\n";
                }
                catch
                {
                   proxString += AppResources.MsgTypeHdr + " \"WriteableTag\" " + AppResources.rejected + "\n";
                }

                try
                {
                    currentApp.IdPairingBluetooth = currentApp.proximityDevice.SubscribeForMessage("Pairing:Bluetooth", messageReceived);
                   proxString += AppResources.MsgTypeHdr + " \"Pairing:Bluetooth\" " + AppResources.subscribed + "\n";
                }
                catch
                {
                   proxString += AppResources.MsgTypeHdr + " \"Pairing:Bluetooth\" " + AppResources.rejected + "\n";
                }

                try
                {
                    currentApp.IdNDEF = currentApp.proximityDevice.SubscribeForMessage("NDEF", ndefTagReceived);
                   proxString += AppResources.MsgTypeHdr + " \"NDEF\" " + AppResources.subscribed + "\n";
                }
                catch
                {
                   proxString += AppResources.MsgTypeHdr + " \"NDEF\" " + AppResources.rejected + "\n";
                }

                try
                {
                    currentApp.IdNDEFUnknown = currentApp.proximityDevice.SubscribeForMessage("NDEF:Unknown", messageReceived);
                   proxString += AppResources.MsgTypeHdr + " \"NDEF:Unknown\" " + AppResources.subscribed + "\n";
                }
                catch
                {
                   proxString += AppResources.MsgTypeHdr + " \"NDEF:Unknown\" " + AppResources.rejected + "\n";
                }

                WriteString(proxString);
                return true;
            }
            else
            {
                proxString += AppResources.ProxDevNotPresent + " ***\n";
                WriteString(proxString);
                return false;
            }
        }

        public void ClearScreen()
        {
            Deployment.Current.Dispatcher.BeginInvoke(() => { MainScreen.Text = ""; });
        }

        public void WriteString(String TextVal)
        {
            Deployment.Current.Dispatcher.BeginInvoke(() => { MainScreen.Text += TextVal; }); 
        }

        private void proximityDeviceArrived(Windows.Networking.Proximity.ProximityDevice device)
        {
            String devArrStr = "*** ";

            ClearScreen();
            devArrStr += AppResources.tagArrivedMsg + " ***\n";

            //if (device.DeviceId.Length > 0)
            //{
            //    devArrStr += " " + AppResources.id + " = " + device.DeviceId;
            //}

            WriteString(devArrStr + "\n");

            //showNoTextMessage = true;
        }

        private void proximityDeviceDeparted(Windows.Networking.Proximity.ProximityDevice device)
        {
            String devDepStr = "*** ";

            devDepStr += AppResources.tagDepartedMsg + " ***\n";

            //if (device.DeviceId.Length > 0)
            //{
            //    devDepStr += " ID = " + device.DeviceId;
            //}

            WriteString(devDepStr + "\n");
        }

        private void messageReceived(ProximityDevice sender, ProximityMessage message)
        {
            String tagAnalysis = "*** " + AppResources.MsgRcvd + " ***\n";

            tagAnalysis += AppResources.MsgTypeHdr + " " + message.MessageType + ".\n\n";
            WriteString(tagAnalysis);
       }

        private void writeableTagReceived(ProximityDevice sender, ProximityMessage message)
        {
            String tagAnalysis = "*** " + AppResources.MsgRcvd + " ***\n";

            tagAnalysis += AppResources.MsgTypeHdr + " " + message.MessageType + ".\n";

            DataReader dataReader = DataReader.FromBuffer(message.Data);
            dataReader.ByteOrder = Windows.Storage.Streams.ByteOrder.LittleEndian;
            int maxLength = dataReader.ReadInt32();

            tagAnalysis += AppResources.MaxLengthHdr + " " + maxLength.ToString() + " bytes\n";
            WriteString(tagAnalysis + "\n");
        }

        private Boolean isMessageBegin(Byte recordFlags) {
            return ((recordFlags & 0x80) != 0);
        }

        private Boolean isMessageEnd(Byte recordFlags) {
            return ((recordFlags & 0x40) != 0);
        }

        private Boolean isChunkedFormat(Byte recordFlags) {
            return ((recordFlags & 0x20) != 0);
        }

        private Boolean isShortRecord(Byte recordFlags)
        {
            return ((recordFlags & 0x10) != 0);
        }

        private Boolean hasIdLength(Byte recordFlags)
        {
            return ((recordFlags & 0x08) != 0);
        }

        private int typeNameFormat(Byte recordFlags) {
            return 0 + (recordFlags & 0x07);
        }

        private String hexVal(Byte rawByte)
        {
            String[] HexCode = new String[16] { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F" };
            String[] returnVal = new String[3];
            returnVal[0] = HexCode[(rawByte >> 4) & 0x0F];
            returnVal[1] = HexCode[rawByte & 0x0F];
            return String.Concat(returnVal[0], returnVal[1]).ToUpper();
        }

        private String appendNfcMessageFlags(Byte recordFlags) {
            String msgFlagText = "";

            if (isMessageEnd(recordFlags)) msgFlagText += AppResources.MsgEndItem + "\n";

            if (isChunkedFormat(recordFlags)) msgFlagText += AppResources.ChunkedFormatItem + "\n";
            else msgFlagText += AppResources.NonChunkedFormatItem + "\n";

            if (isShortRecord(recordFlags)) msgFlagText += AppResources.ShortRecordItem + "\n";
            else msgFlagText += AppResources.LongRecordItem + "\n";

            if (hasIdLength(recordFlags)) msgFlagText += AppResources.HasIdLengthItem + "\n";
            else msgFlagText += AppResources.NoIdLengthItem + "\n";

            msgFlagText += "\n";
            return msgFlagText;
        }

        private void ndefTagReceived(ProximityDevice device, ProximityMessage message) {
            String tagAnalysis = "*** " + AppResources.MsgRcvd + " ***\n";

            DataReader dataReader = DataReader.FromBuffer(message.Data);
            String messageBytes = "";
            String messageText = "";
            Byte[] messageArray = new Byte[message.Data.Length];
            int i;
            int j;
            int ndefRecordCount;
            int messageOffset;
            Byte recordFlags;
            int typeLength;
            String typeString;
            Byte textStatus;
            Byte idType;
            int idLength;
            int payloadLength;
            Byte[] payloadArray;
            Boolean validRecord;
            String remainderHex = "";
            String remainderString = "";
            Byte[] tempArray;
            String wellKnownTypeString = "";
            String textEncoding = "";
            int ianaLength = 0;
            String languageCode = "";
            String payloadString = "";
            String payloadBytes = "";
            String uriPrefixString = "";
            Byte param1 = 0;
            Byte param2 = 0;
            Byte param3 = 0;
            String argsString = "";
            Byte rawByte = 0;

            tagAnalysis += AppResources.MsgTypeHdr + " " + message.MessageType + ".\n";
            tagAnalysis += AppResources.MsgLengthHdr + " " + message.Data.Length.ToString() + " " + AppResources.bytes + ".\n";
            tagAnalysis += "\n";

            for (i = 0; i < message.Data.Length; i++) {
                messageArray[i] = dataReader.ReadByte();
            }

            ndefRecordCount = 0;
            while (messageArray.Length > 2)
            {
                ndefRecordCount++;

                messageOffset = 0;
                recordFlags = messageArray[messageOffset++];
                typeLength = 0;
                typeString = "";
                textStatus = 0x00;
                idType = 0x00;
                idLength = 0;
                payloadLength = 0;
                validRecord = false;

                typeLength = messageArray[messageOffset++];
                payloadLength = 0;
                if (isShortRecord(recordFlags))
                {
                    payloadLength += messageArray[messageOffset++];
                }
                else
                {
                    for (i = 0; i < 4; i++)
                    {
                        payloadLength *= 256;
                        payloadLength += messageArray[messageOffset++];
                    }
                }
                if (hasIdLength(recordFlags)) idLength = messageArray[messageOffset++];

                for (i = 0; i < typeLength; i++)
                {
                    typeString += Convert.ToChar(messageArray[i + messageOffset]);
                }
                messageOffset += typeLength;

                payloadArray = new Byte[payloadLength];
                for (i = 0; i < payloadLength; i++)
                {
                    payloadArray[i] = messageArray[i + messageOffset];
                }
                messageOffset += payloadLength;

                messageBytes = "";
                messageText = "";
                for (j = 0; j < messageArray.Length; j++)
                {
                    rawByte = messageArray[j];
                    messageBytes += hexVal(rawByte) + " ";
                    if ((rawByte < 32) || (rawByte > 127)) messageText += '.';
                    else messageText += Convert.ToChar(rawByte);
                }

                remainderHex = "";
                remainderString = "";
                tempArray = new Byte[messageArray.Length - messageOffset];
                Array.ConstrainedCopy(messageArray, messageOffset, tempArray, 0, messageArray.Length - messageOffset);
                messageArray = tempArray;
                for (i = 0; i < messageArray.Length; i++)
                {
                    remainderHex = String.Concat(remainderHex, hexVal(messageArray[i]));
                    remainderHex = String.Concat(remainderHex, " ");
                    if ((messageArray[i] < 32) || (messageArray[i] > 127)) remainderString = String.Concat(remainderString, '.');
                    else remainderString = String.Concat(remainderString, messageArray[i].ToString());
                }

                tagAnalysis += AppResources.NDEFRecHdr + " " + ndefRecordCount.ToString() + "\n";
                tagAnalysis += "\n";

                tagAnalysis += AppResources.TypeLengthHdr + " " + typeLength.ToString() + " " + AppResources.bytes + ".\n";

                tagAnalysis += AppResources.PayloadLengthHdr + " " + payloadLength.ToString() + " " + AppResources.bytes + ".\n";

                if (idLength > 0) tagAnalysis += AppResources.IdLengthHdr + " " + idLength.ToString() + " " + AppResources.bytes + ".\n";
                else tagAnalysis += AppResources.NoId + "\n";

                tagAnalysis += "\n";

                if (typeNameFormat(recordFlags) == 0x01) { // NFC Forum Well Known Type
                    wellKnownTypeString = AppResources.Unknown + " (" + typeString + ")";

                    if (typeString == "T") { // Text
                        wellKnownTypeString = AppResources.Text;

                        textStatus = payloadArray[0];
                        --payloadLength;
                        tempArray = new Byte[payloadLength];
                        Array.ConstrainedCopy(payloadArray, 1, tempArray, 0, payloadLength);
                        payloadArray = tempArray;

                        if ((textStatus & 0x01) != 0) textEncoding = "UTF16";
                        else textEncoding = "UTF8";
                        ianaLength = 0 + (textStatus & 0x3F);

                        languageCode = "";
                        for (i = 0; i < ianaLength; i++) {
                            languageCode = String.Concat(languageCode, Convert.ToChar(payloadArray[0]));
                            --payloadLength;
                            tempArray = new Byte[payloadLength];
                            Array.ConstrainedCopy(payloadArray, 1, tempArray, 0, payloadLength);
                            payloadArray = tempArray;
                        }
                    } else if (typeString == "Sp") { // Smart Poster
                        wellKnownTypeString = AppResources.SmartPoster;
                    } else if (typeString == "U") { // URI
                        wellKnownTypeString = AppResources.URI;

                        idType = payloadArray[0];
                        --payloadLength;
                        tempArray = new Byte[payloadLength];
                        Array.ConstrainedCopy(payloadArray, 1, tempArray, 0, payloadLength);
                        payloadArray = tempArray;

                        uriPrefixString = "";

                        switch (idType)
                        {
                            case 0x00:
                                uriPrefixString = "";
                                break;

                            case 0x01:
                                uriPrefixString = "http://www.";
                                break;

                            case 0x02:
                                uriPrefixString = "https://www.";
                                break;

                            case 0x03:
                                uriPrefixString = "http://";
                                break;

                            case 0x04:
                                uriPrefixString = "https://";
                                break;

                            case 0x05:
                                uriPrefixString = "tel:";
                                break;

                            case 0x06:
                                uriPrefixString = "mailto:";
                                break;

                            case 0x07:
                                uriPrefixString = "ftp://anonymous:anonymous@";
                                break;

                            case 0x08:
                                uriPrefixString = "ftp://ftp.";
                                break;

                            case 0x09:
                                uriPrefixString = "ftps://";
                                break;

                            case 0x0a:
                                uriPrefixString = "sftp://";
                                break;

                            case 0x0b:
                                uriPrefixString = "smb://";
                                break;

                            case 0x0c:
                                uriPrefixString = "nfs://";
                                break;

                            case 0x0d:
                                uriPrefixString = "ftp://";
                                break;

                            case 0x0e:
                                uriPrefixString = "dav://";
                                break;

                            case 0x0f:
                                uriPrefixString = "news:";
                                break;
                            case 0x10:
                                uriPrefixString = "telnet://";
                                break;

                            case 0x11:
                                uriPrefixString = "imap:";
                                break;

                            case 0x12:
                                uriPrefixString = "rtsp://";
                                break;

                            case 0x13:
                                uriPrefixString = "urn:";
                                break;

                            case 0x14:
                                uriPrefixString = " pop:";
                                break;

                            case 0x15:
                                uriPrefixString = "sip:";
                                break;

                            case 0x16:
                                uriPrefixString = "sips:";
                                break;

                            case 0x17:
                                uriPrefixString = "tftp:";
                                break;

                            case 0x18:
                                uriPrefixString = "btspp://";
                                break;

                            case 0x19:
                                uriPrefixString = "btl2cap://";
                                break;

                            case 0x1a:
                                uriPrefixString = "btgoep://";
                                break;

                            case 0x1b:
                                uriPrefixString = "tcpobex://";
                                break;

                            case 0x1c:
                                uriPrefixString = "irdaobex://";
                                break;

                            case 0x1d:
                                uriPrefixString = "file://";
                                break;

                            case 0x1e:
                                uriPrefixString = "urn:epc:id:";
                                break;

                            case 0x1f:
                                uriPrefixString = "urn:epc:tag";
                                break;

                            case 0x20:
                                uriPrefixString = "urn:epc:pat:";
                                break;

                            case 0x21:
                                uriPrefixString = "urn:epc:raw:";
                                break;

                            case 0x22:
                                uriPrefixString = "urn:epc:";
                                break;

                            case 0x23:
                                uriPrefixString = "urn:nfc:";
                                break;

                            default:
                                uriPrefixString = "RFU";
                                break;
                        }
                    } else if (typeString == "Gc") { // Generic Control
                        wellKnownTypeString = AppResources.GenericCtrl;
                    } else if (typeString == "Hr") { // Handover Request
                        wellKnownTypeString = AppResources.HandoverReq;
                    } else if (typeString == "Hs") { // Handover Select
                        wellKnownTypeString = AppResources.HandoverSel;
                    } else if (typeString == "Hc") { // Handover Carrier
                        wellKnownTypeString = AppResources.HandoverCar;
                    } else if (typeString == "Sg") { // Signature
                        wellKnownTypeString = AppResources.Sig;
                    }

                    tagAnalysis += AppResources.TNF + " = " + Convert.ToString(typeNameFormat(recordFlags), 16) + "\n";
                    tagAnalysis += AppResources.WellKnownTypeHdr + " " + wellKnownTypeString + "\n";
                    tagAnalysis += "\n";

                    if (typeString == "T") {
                        tagAnalysis += AppResources.EncodingHdr + " " + textEncoding + "\n";
                        tagAnalysis += AppResources.LanguageHdr + " " + languageCode + "\n";
                        tagAnalysis += "\n";
                    }
                    else if (typeString == "U") tagAnalysis += AppResources.IdTypeHdr + " " + idType.ToString() + "\n";

                    tagAnalysis += appendNfcMessageFlags(recordFlags);

                    tagAnalysis += AppResources.MsgTextHdr + "\n";
                    tagAnalysis += messageText + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.MsgBytesHdr + "\n";
                    tagAnalysis += messageBytes + "\n";
                    tagAnalysis += "\n";

                    payloadString = "";
                    if (textEncoding == "UTF16")
                    {
                        for (i = 0; i < payloadLength; i += 2)
                        {
                            payloadString += Convert.ToChar(payloadArray[i] + (256 * payloadArray[i + 1]));
                        }
                    }
                    else
                    {
                        for (i = 0; i < payloadLength; i++) payloadString += Convert.ToChar(payloadArray[i]);
                    }
                    if (typeString == "T") {
                        tagAnalysis += AppResources.TextHdr + " " + payloadString + "\n";
                        tagAnalysis += "\n";
                    } else if (typeString == "U") {
                        tagAnalysis += AppResources.URIHdr + " " + uriPrefixString + payloadString + "\n";
                        tagAnalysis += "\n";
                    } else {
                        tagAnalysis += AppResources.PayloadHdr + " " + payloadString + "\n";
                        tagAnalysis += "\n";
                    }
                } else if (typeNameFormat(recordFlags) == 0x02) { // Media Type 
                    tagAnalysis += AppResources.TNF + " = " + Convert.ToString(typeNameFormat(recordFlags), 16) + "\n";
                    tagAnalysis += AppResources.MediaTypeHdr + " " + typeString + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.MsgTextHdr + "\n";
                    tagAnalysis += messageText + "\n";

                    if (typeString.ToLower() == "text/plain") {
                        payloadString = "";
                        for (i = 0; i < payloadLength; i += 2)
                        {
                            payloadString += Convert.ToChar(payloadArray[i] + (256 * payloadArray[i + 1]));
                        }
                        tagAnalysis += AppResources.TextHdr + " " + payloadString + "\n\n";

                    }
                    else if ((typeString.ToLower() == "text/vcard") || (typeString.ToLower() == "text/x-vcard"))
                    {
                        payloadString = "";
                        for (i = 0; i < payloadLength; i++) payloadString += Convert.ToChar(payloadArray[i]);
                        payloadBytes = "";
                        for (j = 0; j < payloadArray.Length ; j++)
                        {
                            rawByte = payloadArray[j];
                            payloadBytes += hexVal(rawByte) + " ";
                        }

                        tagAnalysis += AppResources.vCardDataHdr + "\n";
                        tagAnalysis += payloadString + "\n";
                        tagAnalysis += "\n";

                        tagAnalysis += AppResources.VcardBytesHdr + "\n";
                        tagAnalysis += payloadBytes + "\n";
                        tagAnalysis += "\n";

                        tagAnalysis += Vcard.showVcard(typeString, payloadArray);
                    }
                }
                else if (typeNameFormat(recordFlags) == 0x03)
                { // Absolute URI Type
                    param1 = payloadArray[0];
                    --payloadLength;
                    param2 = payloadArray[1];
                    --payloadLength;
                    param3 = payloadArray[2];
                    --payloadLength;

                    tempArray = new Byte[payloadLength];
                    Array.ConstrainedCopy(payloadArray, 3, tempArray, 0, payloadLength);
                    payloadArray = tempArray;

                    argsString = "";
                    for (i = 0; i < payloadLength; i++)
                    {
                        if ((payloadArray[i] < 32) || (payloadArray[i] > 127)) argsString += '.';
                        else argsString += Convert.ToChar(payloadArray[i]);
                    }

                    tagAnalysis += AppResources.TNF + " = " + Convert.ToString(typeNameFormat(recordFlags), 16) + "\n";
                    tagAnalysis += AppResources.AbsUriType + "\n";
                    tagAnalysis += AppResources.Param1 + " " + hexVal(param1) + "\n";
                    tagAnalysis += AppResources.Param2 + " " + hexVal(param2) + "\n";
                    tagAnalysis += AppResources.Param3 + " " + hexVal(param3) + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += appendNfcMessageFlags(recordFlags);

                    tagAnalysis += AppResources.MsgTextHdr + "\n";
                    tagAnalysis += messageText + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.MsgBytesHdr + "\n";
                    tagAnalysis += messageBytes + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.URIHdr + " " + typeString + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.ArgsHdr + " " + argsString + "\n";
                    tagAnalysis += "\n";
                }
                else if (typeNameFormat(recordFlags) == 0x04)
                { // NFC Forum External Type
                    tagAnalysis += AppResources.TNF + " = " + Convert.ToString(typeNameFormat(recordFlags), 16) + "\n";
                    tagAnalysis += AppResources.ExternalType + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += appendNfcMessageFlags(recordFlags);

                    tagAnalysis += AppResources.MsgTextHdr + "\n";
                    tagAnalysis += messageText + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.MsgBytesHdr + "\n";
                    tagAnalysis += messageBytes + "\n";
                    tagAnalysis += "\n";
                } else { // Currently unsupported Type
                    tagAnalysis += AppResources.UnsupportedType + " " + Convert.ToString(typeNameFormat(recordFlags), 16) + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.TNF + " = " + Convert.ToString(typeNameFormat(recordFlags), 16) + "\n";
                    tagAnalysis += AppResources.UnknownType + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += tagAnalysis += appendNfcMessageFlags(recordFlags);

                    tagAnalysis += AppResources.MsgTextHdr + "\n";
                    tagAnalysis += messageText + "\n";
                    tagAnalysis += "\n";

                    tagAnalysis += AppResources.MsgBytesHdr + "\n";
                    tagAnalysis += messageBytes + "\n";
                    tagAnalysis += "\n";
                }
            }
            WriteString(tagAnalysis);
        }
    }
}