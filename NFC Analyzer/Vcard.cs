using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using NFC_Analyzer.Resources;

namespace NFC_Analyzer
{
    class Vcard
    {
        private static String utf8Decode(Byte[] byteArray) {
            String textString = "";
            int i = 0;
            Byte byte0 = 0;
            Byte byte1 = 0;
            Byte byte2 = 0;
 
            while (i < byteArray.Length) {

                byte0 = byteArray[i];

                if (byte0 < 128)
                {
                    textString += Convert.ToChar(byte0);
                    i++;
                }
                else if ((byte0 > 191) && (byte0 < 224))
                {
                    byte1 = byteArray[i + 1];
                    textString += Convert.ToChar(((byte0 & 0x1F) << 6) | (byte1 & 0x3F));
                    i += 2;
                }
                else
                {
                    byte1 = byteArray[i + 1];
                    byte2 = byteArray[i + 2];
                    textString += Convert.ToChar(((byte0 & 0x0F) << 12) | ((byte1 & 0x3F) << 6) | (byte2 & 63));
                    i += 3;
                }
            }
 
            return textString;
        }

        private static String[] splitUnescaped(String textStr, char splitChar) {
            String[] charSplitArray = textStr.Split(splitChar);
            String[] splitArray = new String[charSplitArray.Length];
            Char[] stringChars = null;
            char lastchar;
            int i = 0;
            int j = 0;

            for (i = 0; i < charSplitArray.Length; i++) {
                if (splitArray[j] != null && splitArray[j].Length > 0) {
                    splitArray[j] += splitChar + charSplitArray[i];
                } else {
                    splitArray[j] = charSplitArray[i];
                }
                if (splitArray[j].Length > 0)
                {
                    stringChars = splitArray[j].ToCharArray();
                    lastchar = stringChars[stringChars.Length - 1];
                    if (lastchar != '\\') j++;
                }
                else
                {
                    j++;
                }
            }

            Array.Resize(ref splitArray, j);            
            return splitArray;
        }

        private static String parseValue(String textStr) {
            String backSlash = Convert.ToChar(0x005C).ToString();
            String escapeComma = backSlash + ",";
            String escapeSemicolon = backSlash + ";";
            String escapeBackslash = backSlash + backSlash;

            textStr = textStr.Replace(escapeComma, ","); // Ref. RFC6350 Section 3.4
            textStr = textStr.Replace(escapeSemicolon, ";"); // Ref. RFC6350 Section 3.4
            textStr = textStr.Replace(escapeBackslash, backSlash); // Ref. RFC6350 Section 3.4

            return textStr;
        }

        private static String parseName(String[] nameArray) {
            String retVal = "";
            Byte[] emQuadBytes = new Byte[3] { 0xE2, 0x80, 0x81 };
            String[] familyArray = null;
            String[] givenArray = null;
            String[] additionalArray = null;
            String[] prefixArray = null;
            String[] suffixArray = null;
            int i;

            retVal += AppResources.NameHdr + "\n";

            if ((nameArray.Length > 0) && (nameArray[0].Length > 0)) {
                familyArray = splitUnescaped(nameArray[0], ',');
                if (familyArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.FamNamesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.FamNameHdr + " ";
                }
                for (i = 0; i < familyArray.Length; i++)
                {
                    retVal += parseValue(familyArray[i]);
                    if (i < familyArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((nameArray.Length > 1) && (nameArray[1].Length > 0))
            {
                givenArray = splitUnescaped(nameArray[1], ',');
                if (givenArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.GivenNamesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.GivenNameHdr + " ";
                }
                for (i = 0; i < givenArray.Length; i++)
                {
                    retVal += parseValue(givenArray[i]);
                    if (i < givenArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((nameArray.Length > 2) && (nameArray[2].Length > 0))
            {
                additionalArray = splitUnescaped(nameArray[2], ',');
                if (additionalArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.AddlNamesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.AddlNameHdr + " ";
                }
                for (i = 0; i < additionalArray.Length; i++)
                {
                    retVal += parseValue(additionalArray[i]);
                    if (i < additionalArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((nameArray.Length > 3) && (nameArray[3].Length > 0))
            {
                prefixArray = splitUnescaped(nameArray[3], ',');
                if (prefixArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.HonPrefixesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.HonPrefixHdr + " ";
                }
                for (i = 0; i < prefixArray.Length; i++)
                {
                    retVal += parseValue(prefixArray[i]);
                    if (i < prefixArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((nameArray.Length > 4) && (nameArray[4].Length > 0))
            {
                suffixArray = splitUnescaped(nameArray[4], ',');
                if (suffixArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.HonSuffixesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.HonSuffixHdr + " ";
                }
                for (i = 0; i < suffixArray.Length; i++)
                {
                    retVal += parseValue(suffixArray[i]);
                    if (i < suffixArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }

            return retVal;
        }

        private static String parseAddress(String[] addressArray)
        {
            String retVal = "";
            Byte[] emQuadBytes = new Byte[3] { 0xE2, 0x80, 0x81 };

            String[] pobArray = null;
            String[] extendedArray = null;
            String[] streetlArray = null;
            String[] localityArray = null;
            String[] regionArray = null;
            String[] postalCodeArray = null;
            String[] countryArray = null;
            int i;

            retVal += AppResources.AddressHdr + "\n";
            if ((addressArray.Length > 0) && (addressArray[0].Length > 0))
            {
                pobArray = splitUnescaped(addressArray[0], ',');
                if (pobArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.POBoxesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.POBoxHdr + " ";
                }
                for (i = 0; i < pobArray.Length; i++)
                {
                    retVal += parseValue(pobArray[i]);
                    if (i < pobArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((addressArray.Length > 1) && (addressArray[1].Length > 0))
            {
                extendedArray = splitUnescaped(addressArray[1], ',');
                if (extendedArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.ExtAddressesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.ExtAddressHdr + " ";
                }
                for (i = 0; i < extendedArray.Length; i++)
                {
                    retVal += parseValue(extendedArray[i]);
                    if (i < extendedArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((addressArray.Length > 2) && (addressArray[2].Length > 0))
            {
                streetlArray = splitUnescaped(addressArray[2], ',');
                if (streetlArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.StreetAddrsHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.StreetAddrHdr + " ";
                }
                for (i = 0; i < streetlArray.Length; i++)
                {
                    retVal += parseValue(streetlArray[i]);
                    if (i < streetlArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((addressArray.Length > 3) && (addressArray[3].Length > 0))
            {
                localityArray = splitUnescaped(addressArray[3], ',');
                if (localityArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.CitiesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.CityHdr + " ";
                }
                for (i = 0; i < localityArray.Length; i++)
                {
                    retVal += parseValue(localityArray[i]);
                    if (i < localityArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((addressArray.Length > 4) && (addressArray[4].Length > 0))
            {
                regionArray = splitUnescaped(addressArray[4], ',');
                if (regionArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.RegionsHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.RegionHdr + " ";
                }
                for (i = 0; i < regionArray.Length; i++)
                {
                    retVal += parseValue(regionArray[i]);
                    if (i < regionArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((addressArray.Length > 5) && (addressArray[5].Length > 0))
            {
                postalCodeArray = splitUnescaped(addressArray[5], ',');
                if (postalCodeArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.PostalCodesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.PostalCodeHdr + " ";
                }
                for (i = 0; i < postalCodeArray.Length; i++)
                {
                    retVal += parseValue(postalCodeArray[i]);
                    if (i < postalCodeArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }
            if ((addressArray.Length > 6) && (addressArray[6].Length > 0))
            {
                 countryArray = splitUnescaped(addressArray[6], ',');
                if (countryArray.Length > 1)
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.CountriesHdr + " ";
                }
                else
                {
                    retVal += utf8Decode(emQuadBytes) + AppResources.CountryHdr + " ";
                }
                for (i = 0; i < countryArray.Length; i++)
                {
                    retVal += parseValue(countryArray[i]);
                    if (i < countryArray.Length - 1) retVal += ", ";
                }
                retVal += "\n";
            }

            return retVal;
        }

        private static String parseXVcard(Byte[] textArray)
        {
            String retVal = "";
            String[] paramArray = null;
            String[] valueArray = null;
            String[] subValueArray = null;
            String[] vCardRecord = null;
            String paramStr = "";
            String valueStr = "";
            String mainParam = "";
            String subParam = "";
            String subValueStr = "";
            Boolean inVcard = false;
            String textString = utf8Decode(textArray);
            int i = 0;

            textString.Replace("\r\n ", ""); // Ref. RFC6350 Section 3.2
            String[] arrXVcard = textString.Split(new string[] { "\r\n"}, StringSplitOptions.RemoveEmptyEntries);
            for (i = 0; i < arrXVcard.Length; i++) {
                vCardRecord = arrXVcard[i].Split(new string[] { ":"}, StringSplitOptions.None);
                if (vCardRecord.Length > 1) {
                    paramStr = vCardRecord[0];
                    paramArray = splitUnescaped(paramStr, ';');
                    valueStr = vCardRecord[1];
                    valueArray = splitUnescaped(valueStr, ';');
                    mainParam = paramArray[0];
                    if (inVcard && mainParam == "END") inVcard = false;
                    if ((inVcard)  && ((vCardRecord.Length < 3) || (valueArray.Length > 1))) {
                        if (mainParam == "N") {
                            retVal += parseName(valueArray);
                        }
                        else if (mainParam == "FN")
                        {
                            retVal += AppResources.FormNameHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "NICKNAME")
                        {
                            retVal += AppResources.NicknameHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "PHOTO")
                        {
                            retVal += AppResources.PhotoHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "BDAY")
                        {
                            retVal += AppResources.BdayHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "ANNIVERSARY")
                        {
                            retVal += AppResources.AnnivHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "GENDER")
                        {
                            retVal += AppResources.GenderHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "ADR")
                        {
                            retVal += parseAddress(valueArray);
                        }
                        else if (mainParam == "TEL")
                        {
                            retVal += AppResources.TelHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "EMAIL")
                        {
                            retVal += AppResources.EmailHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "IMPP")
                        {
                            retVal += AppResources.ImppUriHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "LANG")
                        {
                            retVal += AppResources.LanguageHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "TZ")
                        {
                            retVal += AppResources.TzHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "GEO")
                        {
                            retVal += AppResources.GeoCodeHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "TITLE")
                        {
                            retVal += AppResources.TitleHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "ROLE")
                        {
                            retVal += AppResources.RoleHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "LOGO")
                        {
                            retVal += AppResources.LogoHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "ORG")
                        {
                            retVal += AppResources.OrgHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "MEMBER")
                        {
                            retVal += AppResources.MemberHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "RELATED")
                        {
                            retVal += AppResources.RelatedHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "CATEGORIES")
                        {
                            retVal += AppResources.TagsHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "NOTE")
                        {
                            retVal += AppResources.NoteHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "PRODID")
                        {
                            retVal += AppResources.ProdIdHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "REV")
                        {
                            retVal += AppResources.RevHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "SOUND")
                        {
                            retVal += AppResources.SndUriHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "UID")
                        {
                            retVal += AppResources.UidHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "CLIENTPIDMAP")
                        {
                            retVal += AppResources.CpidMapHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "URL")
                        {
                            retVal += AppResources.UrlHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "VERSION")
                        {
                            retVal += AppResources.VcVersionHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "KEY")
                        {
                            retVal += AppResources.PubKeyOrAuthCertHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "FBURL")
                        {
                            retVal += AppResources.BusyTimeUriHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "CALADRURI")
                        {
                            retVal += AppResources.CalUserAddrUriHdr + ": " + parseValue(valueStr) + "\n";
                        }
                        else if (mainParam == "CALURI")
                        {
                            retVal += AppResources.CalUriHdr + ": " + parseValue(valueStr) + "\n";
                        } else {
                            retVal += mainParam + ": " + parseValue(valueStr) + "\n";
                        }
                    }
                    if (mainParam == "BEGIN") inVcard = true;
                    if (vCardRecord.Length > 2) {
                        if (valueArray.Length == 1)
                        {
                            subParam = valueStr;
                            subValueStr = vCardRecord[2];
                            subValueArray = splitUnescaped(subValueStr, ';');
                        }
                        else
                        {
                            subParam = paramArray[paramArray.Length - 1];
                            subValueStr = vCardRecord[2];
                            subValueArray = splitUnescaped(subValueStr, ';');
                        }
                        if (mainParam == "ADR") {
                            if (subParam == "HOME") {
                                retVal += AppResources.HomeAddrHdr + " " + parseValue(subValueStr) + "\n";
                            }
                            else
                            {
                                retVal += subParam +  " " + AppResources.AddressHdr + " " + parseValue(subValueStr) + "\n";
                            }
                        }
                        else if (mainParam == "URL")
                        {
                            if (subParam == "fb") {
                                retVal += AppResources.FacebookUrlHdr + " " +parseValue(subValueStr) + "\n";
                            } else {
                                retVal += subParam + " " + AppResources.UrlHdr + " " + parseValue(subValueStr) + "\n";
                            }
                        }
                        else
                        {
                            retVal += AppResources.VcardParamHdr + " " + mainParam + " : " + subParam + "\n";
                        }
                    }
                }
            }
            retVal += "\n";

            return retVal;
        }

        public static String showVcard(String typeString, Byte[]textArray) {
            String retVal = "";

            if ((typeString.ToLower() == "text/vcard") || (typeString.ToLower() == "text/x-vcard"))
            {
                retVal += parseXVcard(textArray);
            }

            return retVal;
        }
    }
}
