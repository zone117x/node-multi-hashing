// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2015 The Dropcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OLD_DROPCOIN_UINT256_H
#define OLD_DROPCOIN_UINT256_H

#include <stdint.h>
#include <stdio.h>

namespace olduint {

/** Base class without constructors for uint256 and uint160.
 * This makes the compiler let you use it in a union.
 */
    template<unsigned int BITS>
    class base_uint
    {
    protected:
        enum { WIDTH=BITS/32 };
        uint32_t pn[WIDTH];
    public:

        bool operator!() const
        {
            for (int i = 0; i < WIDTH; i++)
                if (pn[i] != 0)
                    return false;
            return true;
        }

        const base_uint operator~() const
        {
            base_uint ret;
            for (int i = 0; i < WIDTH; i++)
                ret.pn[i] = ~pn[i];
            return ret;
        }

        const base_uint operator-() const
        {
            base_uint ret;
            for (int i = 0; i < WIDTH; i++)
                ret.pn[i] = ~pn[i];
            ret++;
            return ret;
        }

        double getdouble() const
        {
            double ret = 0.0;
            double fact = 1.0;
            for (int i = 0; i < WIDTH; i++) {
                ret += fact * pn[i];
                fact *= 4294967296.0;
            }
            return ret;
        }

        uint32_t getinnerint(unsigned int nIndex) const
        {
            return pn[nIndex % WIDTH];
        }

        base_uint& operator=(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
            return *this;
        }

        base_uint& operator^=(const base_uint& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] ^= b.pn[i];
            return *this;
        }

        base_uint& operator&=(const base_uint& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] &= b.pn[i];
            return *this;
        }

        base_uint& operator|=(const base_uint& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] |= b.pn[i];
            return *this;
        }

        base_uint& operator^=(uint64_t b)
        {
            pn[0] ^= (unsigned int)b;
            pn[1] ^= (unsigned int)(b >> 32);
            return *this;
        }

        base_uint& operator|=(uint64_t b)
        {
            pn[0] |= (unsigned int)b;
            pn[1] |= (unsigned int)(b >> 32);
            return *this;
        }

        base_uint& operator<<=(unsigned int shift)
        {
            base_uint a(*this);
            for (int i = 0; i < WIDTH; i++)
                pn[i] = 0;
            int k = shift / 32;
            shift = shift % 32;
            for (int i = 0; i < WIDTH; i++)
            {
                if (i+k+1 < WIDTH && shift != 0)
                    pn[i+k+1] |= (a.pn[i] >> (32-shift));
                if (i+k < WIDTH)
                    pn[i+k] |= (a.pn[i] << shift);
            }
            return *this;
        }

        base_uint& operator>>=(unsigned int shift)
        {
            base_uint a(*this);
            for (int i = 0; i < WIDTH; i++)
                pn[i] = 0;
            int k = shift / 32;
            shift = shift % 32;
            for (int i = 0; i < WIDTH; i++)
            {
                if (i-k-1 >= 0 && shift != 0)
                    pn[i-k-1] |= (a.pn[i] << (32-shift));
                if (i-k >= 0)
                    pn[i-k] |= (a.pn[i] >> shift);
            }
            return *this;
        }

        base_uint& operator+=(const base_uint& b)
        {
            uint64_t carry = 0;
            for (int i = 0; i < WIDTH; i++)
            {
                uint64_t n = carry + pn[i] + b.pn[i];
                pn[i] = n & 0xffffffff;
                carry = n >> 32;
            }
            return *this;
        }

        base_uint& operator-=(const base_uint& b)
        {
            *this += -b;
            return *this;
        }

        base_uint& operator+=(uint64_t b64)
        {
            base_uint b;
            b = b64;
            *this += b;
            return *this;
        }

        base_uint& operator-=(uint64_t b64)
        {
            base_uint b;
            b = b64;
            *this += -b;
            return *this;
        }


        base_uint& operator++()
        {
            // prefix operator
            int i = 0;
            while (++pn[i] == 0 && i < WIDTH-1)
                i++;
            return *this;
        }

        const base_uint operator++(int)
        {
            // postfix operator
            const base_uint ret = *this;
            ++(*this);
            return ret;
        }

        base_uint& operator--()
        {
            // prefix operator
            int i = 0;
            while (--pn[i] == (uint32_t)-1 && i < WIDTH-1)
                i++;
            return *this;
        }

        const base_uint operator--(int)
        {
            // postfix operator
            const base_uint ret = *this;
            --(*this);
            return ret;
        }


        friend inline bool operator<(const base_uint& a, const base_uint& b)
        {
            for (int i = base_uint::WIDTH-1; i >= 0; i--)
            {
                if (a.pn[i] < b.pn[i])
                    return true;
                else if (a.pn[i] > b.pn[i])
                    return false;
            }
            return false;
        }

        friend inline bool operator<=(const base_uint& a, const base_uint& b)
        {
            for (int i = base_uint::WIDTH-1; i >= 0; i--)
            {
                if (a.pn[i] < b.pn[i])
                    return true;
                else if (a.pn[i] > b.pn[i])
                    return false;
            }
            return true;
        }

        friend inline bool operator>(const base_uint& a, const base_uint& b)
        {
            for (int i = base_uint::WIDTH-1; i >= 0; i--)
            {
                if (a.pn[i] > b.pn[i])
                    return true;
                else if (a.pn[i] < b.pn[i])
                    return false;
            }
            return false;
        }

        friend inline bool operator>=(const base_uint& a, const base_uint& b)
        {
            for (int i = base_uint::WIDTH-1; i >= 0; i--)
            {
                if (a.pn[i] > b.pn[i])
                    return true;
                else if (a.pn[i] < b.pn[i])
                    return false;
            }
            return true;
        }

        friend inline bool operator==(const base_uint& a, const base_uint& b)
        {
            for (int i = 0; i < base_uint::WIDTH; i++)
                if (a.pn[i] != b.pn[i])
                    return false;
            return true;
        }

        friend inline bool operator==(const base_uint& a, uint64_t b)
        {
            if (a.pn[0] != (unsigned int)b)
                return false;
            if (a.pn[1] != (unsigned int)(b >> 32))
                return false;
            for (int i = 2; i < base_uint::WIDTH; i++)
                if (a.pn[i] != 0)
                    return false;
            return true;
        }

        friend inline bool operator!=(const base_uint& a, const base_uint& b)
        {
            return (!(a == b));
        }

        friend inline bool operator!=(const base_uint& a, uint64_t b)
        {
            return (!(a == b));
        }

        unsigned char* begin()
        {
            return (unsigned char*)&pn[0];
        }

        unsigned char* end()
        {
            return (unsigned char*)&pn[WIDTH];
        }

        const unsigned char* begin() const
        {
            return (unsigned char*)&pn[0];
        }

        const unsigned char* end() const
        {
            return (unsigned char*)&pn[WIDTH];
        }

        unsigned int size() const
        {
            return sizeof(pn);
        }

        uint64_t Get64(int n=0) const
        {
            return pn[2*n] | (uint64_t)pn[2*n+1] << 32;
        }

        uint64_t GetLow64() const
        {
            assert(WIDTH >= 2);
            return pn[0] | (uint64_t)pn[1] << 32;
        }

//    unsigned int GetSerializeSize(int nType=0, int nVersion=PROTOCOL_VERSION) const
        unsigned int GetSerializeSize(int nType, int nVersion) const
        {
            return sizeof(pn);
        }

        template<typename Stream>
//    void Serialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION) const
        void Serialize(Stream& s, int nType, int nVersion) const
        {
            s.write((char*)pn, sizeof(pn));
        }

        template<typename Stream>
//    void Unserialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION)
        void Unserialize(Stream& s, int nType, int nVersion)
        {
            s.read((char*)pn, sizeof(pn));
        }


        friend class uint160;
        friend class uint256;
        friend class uint512;
    };

    typedef base_uint<160> base_uint160;
    typedef base_uint<256> base_uint256;
    typedef base_uint<512> base_uint512;



//
// uint160 and uint256 could be implemented as templates, but to keep
// compile errors and debugging cleaner, they're copy and pasted.
//



//////////////////////////////////////////////////////////////////////////////
//
// uint160
//

/** 160-bit unsigned integer */
    class uint160 : public base_uint160
    {
    public:
        typedef base_uint160 basetype;

        uint160()
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = 0;
        }

        uint160(const basetype& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
        }

        uint160& operator=(const basetype& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
            return *this;
        }

        uint160(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
        }

        uint160& operator=(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
            return *this;
        }
    };

    inline bool operator==(const uint160& a, uint64_t b)                         { return (base_uint160)a == b; }
    inline bool operator!=(const uint160& a, uint64_t b)                         { return (base_uint160)a != b; }
    inline const uint160 operator<<(const base_uint160& a, unsigned int shift)   { return uint160(a) <<= shift; }
    inline const uint160 operator>>(const base_uint160& a, unsigned int shift)   { return uint160(a) >>= shift; }
    inline const uint160 operator<<(const uint160& a, unsigned int shift)        { return uint160(a) <<= shift; }
    inline const uint160 operator>>(const uint160& a, unsigned int shift)        { return uint160(a) >>= shift; }

    inline const uint160 operator^(const base_uint160& a, const base_uint160& b) { return uint160(a) ^= b; }
    inline const uint160 operator&(const base_uint160& a, const base_uint160& b) { return uint160(a) &= b; }
    inline const uint160 operator|(const base_uint160& a, const base_uint160& b) { return uint160(a) |= b; }
    inline const uint160 operator+(const base_uint160& a, const base_uint160& b) { return uint160(a) += b; }
    inline const uint160 operator-(const base_uint160& a, const base_uint160& b) { return uint160(a) -= b; }

    inline bool operator<(const base_uint160& a, const uint160& b)               { return (base_uint160)a <  (base_uint160)b; }
    inline bool operator<=(const base_uint160& a, const uint160& b)              { return (base_uint160)a <= (base_uint160)b; }
    inline bool operator>(const base_uint160& a, const uint160& b)               { return (base_uint160)a >  (base_uint160)b; }
    inline bool operator>=(const base_uint160& a, const uint160& b)              { return (base_uint160)a >= (base_uint160)b; }
    inline bool operator==(const base_uint160& a, const uint160& b)              { return (base_uint160)a == (base_uint160)b; }
    inline bool operator!=(const base_uint160& a, const uint160& b)              { return (base_uint160)a != (base_uint160)b; }
    inline const uint160 operator^(const base_uint160& a, const uint160& b)      { return (base_uint160)a ^  (base_uint160)b; }
    inline const uint160 operator&(const base_uint160& a, const uint160& b)      { return (base_uint160)a &  (base_uint160)b; }
    inline const uint160 operator|(const base_uint160& a, const uint160& b)      { return (base_uint160)a |  (base_uint160)b; }
    inline const uint160 operator+(const base_uint160& a, const uint160& b)      { return (base_uint160)a +  (base_uint160)b; }
    inline const uint160 operator-(const base_uint160& a, const uint160& b)      { return (base_uint160)a -  (base_uint160)b; }

    inline bool operator<(const uint160& a, const base_uint160& b)               { return (base_uint160)a <  (base_uint160)b; }
    inline bool operator<=(const uint160& a, const base_uint160& b)              { return (base_uint160)a <= (base_uint160)b; }
    inline bool operator>(const uint160& a, const base_uint160& b)               { return (base_uint160)a >  (base_uint160)b; }
    inline bool operator>=(const uint160& a, const base_uint160& b)              { return (base_uint160)a >= (base_uint160)b; }
    inline bool operator==(const uint160& a, const base_uint160& b)              { return (base_uint160)a == (base_uint160)b; }
    inline bool operator!=(const uint160& a, const base_uint160& b)              { return (base_uint160)a != (base_uint160)b; }
    inline const uint160 operator^(const uint160& a, const base_uint160& b)      { return (base_uint160)a ^  (base_uint160)b; }
    inline const uint160 operator&(const uint160& a, const base_uint160& b)      { return (base_uint160)a &  (base_uint160)b; }
    inline const uint160 operator|(const uint160& a, const base_uint160& b)      { return (base_uint160)a |  (base_uint160)b; }
    inline const uint160 operator+(const uint160& a, const base_uint160& b)      { return (base_uint160)a +  (base_uint160)b; }
    inline const uint160 operator-(const uint160& a, const base_uint160& b)      { return (base_uint160)a -  (base_uint160)b; }

    inline bool operator<(const uint160& a, const uint160& b)                    { return (base_uint160)a <  (base_uint160)b; }
    inline bool operator<=(const uint160& a, const uint160& b)                   { return (base_uint160)a <= (base_uint160)b; }
    inline bool operator>(const uint160& a, const uint160& b)                    { return (base_uint160)a >  (base_uint160)b; }
    inline bool operator>=(const uint160& a, const uint160& b)                   { return (base_uint160)a >= (base_uint160)b; }
    inline bool operator==(const uint160& a, const uint160& b)                   { return (base_uint160)a == (base_uint160)b; }
    inline bool operator!=(const uint160& a, const uint160& b)                   { return (base_uint160)a != (base_uint160)b; }
    inline const uint160 operator^(const uint160& a, const uint160& b)           { return (base_uint160)a ^  (base_uint160)b; }
    inline const uint160 operator&(const uint160& a, const uint160& b)           { return (base_uint160)a &  (base_uint160)b; }
    inline const uint160 operator|(const uint160& a, const uint160& b)           { return (base_uint160)a |  (base_uint160)b; }
    inline const uint160 operator+(const uint160& a, const uint160& b)           { return (base_uint160)a +  (base_uint160)b; }
    inline const uint160 operator-(const uint160& a, const uint160& b)           { return (base_uint160)a -  (base_uint160)b; }



//////////////////////////////////////////////////////////////////////////////
//
// uint256
//

/** 256-bit unsigned integer */
    class uint256 : public base_uint256
    {
    public:
        typedef base_uint256 basetype;

        uint256()
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = 0;
        }

        uint256(const basetype& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
        }

        uint256& operator=(const basetype& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
            return *this;
        }

        uint256(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
        }

        uint256& operator=(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
            return *this;
        }
    };

    inline bool operator==(const uint256& a, uint64_t b)                          { return (base_uint256)a == b; }
    inline bool operator!=(const uint256& a, uint64_t b)                          { return (base_uint256)a != b; }
    inline const uint256 operator<<(const base_uint256& a, unsigned int shift)   { return uint256(a) <<= shift; }
    inline const uint256 operator>>(const base_uint256& a, unsigned int shift)   { return uint256(a) >>= shift; }
    inline const uint256 operator<<(const uint256& a, unsigned int shift)        { return uint256(a) <<= shift; }
    inline const uint256 operator>>(const uint256& a, unsigned int shift)        { return uint256(a) >>= shift; }

    inline const uint256 operator^(const base_uint256& a, const base_uint256& b) { return uint256(a) ^= b; }
    inline const uint256 operator&(const base_uint256& a, const base_uint256& b) { return uint256(a) &= b; }
    inline const uint256 operator|(const base_uint256& a, const base_uint256& b) { return uint256(a) |= b; }
    inline const uint256 operator+(const base_uint256& a, const base_uint256& b) { return uint256(a) += b; }
    inline const uint256 operator-(const base_uint256& a, const base_uint256& b) { return uint256(a) -= b; }

    inline bool operator<(const base_uint256& a, const uint256& b)          { return (base_uint256)a <  (base_uint256)b; }
    inline bool operator<=(const base_uint256& a, const uint256& b)         { return (base_uint256)a <= (base_uint256)b; }
    inline bool operator>(const base_uint256& a, const uint256& b)          { return (base_uint256)a >  (base_uint256)b; }
    inline bool operator>=(const base_uint256& a, const uint256& b)         { return (base_uint256)a >= (base_uint256)b; }
    inline bool operator==(const base_uint256& a, const uint256& b)         { return (base_uint256)a == (base_uint256)b; }
    inline bool operator!=(const base_uint256& a, const uint256& b)         { return (base_uint256)a != (base_uint256)b; }
    inline const uint256 operator^(const base_uint256& a, const uint256& b) { return (base_uint256)a ^  (base_uint256)b; }
    inline const uint256 operator&(const base_uint256& a, const uint256& b) { return (base_uint256)a &  (base_uint256)b; }
    inline const uint256 operator|(const base_uint256& a, const uint256& b) { return (base_uint256)a |  (base_uint256)b; }
    inline const uint256 operator+(const base_uint256& a, const uint256& b) { return (base_uint256)a +  (base_uint256)b; }
    inline const uint256 operator-(const base_uint256& a, const uint256& b) { return (base_uint256)a -  (base_uint256)b; }

    inline bool operator<(const uint256& a, const base_uint256& b)          { return (base_uint256)a <  (base_uint256)b; }
    inline bool operator<=(const uint256& a, const base_uint256& b)         { return (base_uint256)a <= (base_uint256)b; }
    inline bool operator>(const uint256& a, const base_uint256& b)          { return (base_uint256)a >  (base_uint256)b; }
    inline bool operator>=(const uint256& a, const base_uint256& b)         { return (base_uint256)a >= (base_uint256)b; }
    inline bool operator==(const uint256& a, const base_uint256& b)         { return (base_uint256)a == (base_uint256)b; }
    inline bool operator!=(const uint256& a, const base_uint256& b)         { return (base_uint256)a != (base_uint256)b; }
    inline const uint256 operator^(const uint256& a, const base_uint256& b) { return (base_uint256)a ^  (base_uint256)b; }
    inline const uint256 operator&(const uint256& a, const base_uint256& b) { return (base_uint256)a &  (base_uint256)b; }
    inline const uint256 operator|(const uint256& a, const base_uint256& b) { return (base_uint256)a |  (base_uint256)b; }
    inline const uint256 operator+(const uint256& a, const base_uint256& b) { return (base_uint256)a +  (base_uint256)b; }
    inline const uint256 operator-(const uint256& a, const base_uint256& b) { return (base_uint256)a -  (base_uint256)b; }

    inline bool operator<(const uint256& a, const uint256& b)               { return (base_uint256)a <  (base_uint256)b; }
    inline bool operator<=(const uint256& a, const uint256& b)              { return (base_uint256)a <= (base_uint256)b; }
    inline bool operator>(const uint256& a, const uint256& b)               { return (base_uint256)a >  (base_uint256)b; }
    inline bool operator>=(const uint256& a, const uint256& b)              { return (base_uint256)a >= (base_uint256)b; }
    inline bool operator==(const uint256& a, const uint256& b)              { return (base_uint256)a == (base_uint256)b; }
    inline bool operator!=(const uint256& a, const uint256& b)              { return (base_uint256)a != (base_uint256)b; }
    inline const uint256 operator^(const uint256& a, const uint256& b)      { return (base_uint256)a ^  (base_uint256)b; }
    inline const uint256 operator&(const uint256& a, const uint256& b)      { return (base_uint256)a &  (base_uint256)b; }
    inline const uint256 operator|(const uint256& a, const uint256& b)      { return (base_uint256)a |  (base_uint256)b; }
    inline const uint256 operator+(const uint256& a, const uint256& b)      { return (base_uint256)a +  (base_uint256)b; }
    inline const uint256 operator-(const uint256& a, const uint256& b)      { return (base_uint256)a -  (base_uint256)b; }



//////////////////////////////////////////////////////////////////////////////
//
// uint512
//

/** 512-bit unsigned integer */
    class uint512 : public base_uint512
    {
    public:
        typedef base_uint512 basetype;

        uint512()
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = 0;
        }

        uint512(const basetype& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
        }

        uint512& operator=(const basetype& b)
        {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
            return *this;
        }

        uint512(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
        }

        uint512& operator=(uint64_t b)
        {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
            return *this;
        }

        uint256 trim256() const
        {
            uint256 ret;
            for (unsigned int i = 0; i < uint256::WIDTH; i++){
                ret.pn[i] = pn[i];
            }
            return ret;
        }
    };

    inline bool operator==(const uint512& a, uint64_t b)                           { return (base_uint512)a == b; }
    inline bool operator!=(const uint512& a, uint64_t b)                           { return (base_uint512)a != b; }
    inline const uint512 operator<<(const base_uint512& a, unsigned int shift)   { return uint512(a) <<= shift; }
    inline const uint512 operator>>(const base_uint512& a, unsigned int shift)   { return uint512(a) >>= shift; }
    inline const uint512 operator<<(const uint512& a, unsigned int shift)        { return uint512(a) <<= shift; }
    inline const uint512 operator>>(const uint512& a, unsigned int shift)        { return uint512(a) >>= shift; }

    inline const uint512 operator^(const base_uint512& a, const base_uint512& b) { return uint512(a) ^= b; }
    inline const uint512 operator&(const base_uint512& a, const base_uint512& b) { return uint512(a) &= b; }
    inline const uint512 operator|(const base_uint512& a, const base_uint512& b) { return uint512(a) |= b; }
    inline const uint512 operator+(const base_uint512& a, const base_uint512& b) { return uint512(a) += b; }
    inline const uint512 operator-(const base_uint512& a, const base_uint512& b) { return uint512(a) -= b; }

    inline bool operator<(const base_uint512& a, const uint512& b)          { return (base_uint512)a <  (base_uint512)b; }
    inline bool operator<=(const base_uint512& a, const uint512& b)         { return (base_uint512)a <= (base_uint512)b; }
    inline bool operator>(const base_uint512& a, const uint512& b)          { return (base_uint512)a >  (base_uint512)b; }
    inline bool operator>=(const base_uint512& a, const uint512& b)         { return (base_uint512)a >= (base_uint512)b; }
    inline bool operator==(const base_uint512& a, const uint512& b)         { return (base_uint512)a == (base_uint512)b; }
    inline bool operator!=(const base_uint512& a, const uint512& b)         { return (base_uint512)a != (base_uint512)b; }
    inline const uint512 operator^(const base_uint512& a, const uint512& b) { return (base_uint512)a ^  (base_uint512)b; }
    inline const uint512 operator&(const base_uint512& a, const uint512& b) { return (base_uint512)a &  (base_uint512)b; }
    inline const uint512 operator|(const base_uint512& a, const uint512& b) { return (base_uint512)a |  (base_uint512)b; }
    inline const uint512 operator+(const base_uint512& a, const uint512& b) { return (base_uint512)a +  (base_uint512)b; }
    inline const uint512 operator-(const base_uint512& a, const uint512& b) { return (base_uint512)a -  (base_uint512)b; }

    inline bool operator<(const uint512& a, const base_uint512& b)          { return (base_uint512)a <  (base_uint512)b; }
    inline bool operator<=(const uint512& a, const base_uint512& b)         { return (base_uint512)a <= (base_uint512)b; }
    inline bool operator>(const uint512& a, const base_uint512& b)          { return (base_uint512)a >  (base_uint512)b; }
    inline bool operator>=(const uint512& a, const base_uint512& b)         { return (base_uint512)a >= (base_uint512)b; }
    inline bool operator==(const uint512& a, const base_uint512& b)         { return (base_uint512)a == (base_uint512)b; }
    inline bool operator!=(const uint512& a, const base_uint512& b)         { return (base_uint512)a != (base_uint512)b; }
    inline const uint512 operator^(const uint512& a, const base_uint512& b) { return (base_uint512)a ^  (base_uint512)b; }
    inline const uint512 operator&(const uint512& a, const base_uint512& b) { return (base_uint512)a &  (base_uint512)b; }
    inline const uint512 operator|(const uint512& a, const base_uint512& b) { return (base_uint512)a |  (base_uint512)b; }
    inline const uint512 operator+(const uint512& a, const base_uint512& b) { return (base_uint512)a +  (base_uint512)b; }
    inline const uint512 operator-(const uint512& a, const base_uint512& b) { return (base_uint512)a -  (base_uint512)b; }

    inline bool operator<(const uint512& a, const uint512& b)               { return (base_uint512)a <  (base_uint512)b; }
    inline bool operator<=(const uint512& a, const uint512& b)              { return (base_uint512)a <= (base_uint512)b; }
    inline bool operator>(const uint512& a, const uint512& b)               { return (base_uint512)a >  (base_uint512)b; }
    inline bool operator>=(const uint512& a, const uint512& b)              { return (base_uint512)a >= (base_uint512)b; }
    inline bool operator==(const uint512& a, const uint512& b)              { return (base_uint512)a == (base_uint512)b; }
    inline bool operator!=(const uint512& a, const uint512& b)              { return (base_uint512)a != (base_uint512)b; }
    inline const uint512 operator^(const uint512& a, const uint512& b)      { return (base_uint512)a ^  (base_uint512)b; }
    inline const uint512 operator&(const uint512& a, const uint512& b)      { return (base_uint512)a &  (base_uint512)b; }
    inline const uint512 operator|(const uint512& a, const uint512& b)      { return (base_uint512)a |  (base_uint512)b; }
    inline const uint512 operator+(const uint512& a, const uint512& b)      { return (base_uint512)a +  (base_uint512)b; }
    inline const uint512 operator-(const uint512& a, const uint512& b)      { return (base_uint512)a -  (base_uint512)b; }

} //namespace olduint

#endif // OLD_DROPCOIN_UINT256_H