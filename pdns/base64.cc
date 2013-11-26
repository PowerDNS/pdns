#include "base64.hh"
#include <inttypes.h>
#include "dns.hh"
namespace anonpdns {
char B64Decode1(char cInChar)
{
  // The incoming character will be A-Z, a-z, 0-9, +, /, or =.
  // The idea is to quickly determine which grouping the
  // letter belongs to and return the associated value
  // without having to search the global encoding string
  // (the value we're looking for would be the resulting
  // index into that string).
  //
  // To do that, we'll play some tricks...
  unsigned char iIndex = '\0';
  switch ( cInChar ) {
  case '+':
    iIndex = 62;
    break;

  case '/':
    iIndex = 63;
    break;

  case '=':
    iIndex = 0;
    break;

  default:
    // Must be 'A'-'Z', 'a'-'z', '0'-'9', or an error...
    //
    // Numerically, small letters are "greater" in value than
    // capital letters and numerals (ASCII value), and capital
    // letters are "greater" than numerals (again, ASCII value),
    // so we check for numerals first, then capital letters,
    // and finally small letters.
    iIndex = '9' - cInChar;
    if ( iIndex > 0x3F ) {
      // Not from '0' to '9'...
      iIndex = 'Z' - cInChar;
      if ( iIndex > 0x3F ) {
        // Not from 'A' to 'Z'...
        iIndex = 'z' - cInChar;
        if ( iIndex > 0x3F ) {
          // Invalid character...cannot
          // decode!
          iIndex = 0x80; // set the high bit
        } // if
        else {
          // From 'a' to 'z'
          iIndex = (('z' - iIndex) - 'a') + 26;
        } // else
      } // if
      else {
        // From 'A' to 'Z'
        iIndex = ('Z' - iIndex) - 'A';
      } // else
    } // if
    else {
      // Adjust the index...
      iIndex = (('9' - iIndex) - '0') + 52;
    } // else
    break;

  } // switch

  return iIndex;
}

inline char B64Encode1(unsigned char uc)
{
  if (uc < 26)
    {
      return 'A'+uc;
    }
  if (uc < 52)
    {
      return 'a'+(uc-26);
    }
  if (uc < 62)
    {
      return '0'+(uc-52);
    }
  if (uc == 62)
    {
      return '+';
    }
  return '/';
};



}
using namespace anonpdns;

int B64Decode(const std::string& strInput, std::string& strOutput)
{
  // Set up a decoding buffer
  long cBuf = 0;
  char* pBuf = (char*)&cBuf;

  // Decoding management...
  int iBitGroup = 0, iInNum = 0;

  // While there are characters to process...
  //
  // We'll decode characters in blocks of 4, as
  // there are 4 groups of 6 bits in 3 bytes. The
  // incoming Base64 character is first decoded, and
  // then it is inserted into the decode buffer
  // (with any relevant shifting, as required).
  // Later, after all 3 bytes have been reconstituted,
  // we assign them to the output string, ultimately
  // to be returned as the original message.
  int iInSize = strInput.size();
  unsigned char cChar = '\0';
  uint8_t pad = 0;
  while ( iInNum < iInSize ) {
    // Fill the decode buffer with 4 groups of 6 bits
    cBuf = 0; // clear
    pad = 0;
    for ( iBitGroup = 0; iBitGroup < 4; ++iBitGroup ) {
      if ( iInNum < iInSize ) {
        // Decode a character
       if(strInput.at(iInNum)=='=')
         pad++;
        while(isspace(strInput.at(iInNum)))
          iInNum++;
        cChar = B64Decode1(strInput.at(iInNum++));

      } // if
      else {
        // Decode a padded zero
        cChar = '\0';
      } // else

      // Check for valid decode
      if ( cChar > 0x7F )
        return -1;

      // Adjust the bits
      switch ( iBitGroup ) {
      case 0:
        // The first group is copied into
        // the least significant 6 bits of
        // the decode buffer...these 6 bits
        // will eventually shift over to be
        // the most significant bits of the
        // third byte.
        cBuf = cBuf | cChar;
        break;

      default:
        // For groupings 1-3, simply shift
        // the bits in the decode buffer over
        // by 6 and insert the 6 from the
        // current decode character.
        cBuf = (cBuf << 6) | cChar;
        break;

      } // switch
    } // for

    // Interpret the resulting 3 bytes...note there
    // may have been padding, so those padded bytes
    // are actually ignored.
#if BYTE_ORDER == BIG_ENDIAN
    strOutput += pBuf[sizeof(long)-3];
    strOutput += pBuf[sizeof(long)-2];
    strOutput += pBuf[sizeof(long)-1];
#else
    strOutput += pBuf[2];
    strOutput += pBuf[1];
    strOutput += pBuf[0];
#endif
                        
  } // while
  if(pad)
    strOutput.resize(strOutput.length()-pad);

  return 1;
}

/*
www.kbcafe.com
Copyright 2001-2002 Randy Charles Morin
The Encode static method takes an array of 8-bit values and returns a base-64 stream.
*/


std::string Base64Encode (const std::string& vby)
{
  std::string retval;
  if (vby.size () == 0)
    {
      return retval;
    };
  for (unsigned int i = 0; i < vby.size (); i += 3)
    {
      unsigned char by1 = 0, by2 = 0, by3 = 0;
      by1 = vby[i];
      if (i + 1 < vby.size ())
        {
          by2 = vby[i + 1];
        };
      if (i + 2 < vby.size ())
        {
          by3 = vby[i + 2];
        }
      unsigned char by4 = 0, by5 = 0, by6 = 0, by7 = 0;
      by4 = by1 >> 2;
      by5 = ((by1 & 0x3) << 4) | (by2 >> 4);
      by6 = ((by2 & 0xf) << 2) | (by3 >> 6);
      by7 = by3 & 0x3f;
      retval += B64Encode1 (by4);
      retval += B64Encode1 (by5);
      if (i + 1 < vby.size ())
        {
          retval += B64Encode1 (by6);
        }
      else
        {
          retval += "=";
        };
      if (i + 2 < vby.size ())
        {
          retval += B64Encode1 (by7);
        }
      else
        {
          retval += "=";
        };
      /*      if ((i % (76 / 4 * 3)) == 0)
        {
          retval += "\r\n";
          }*/
    };
  return retval;
};
