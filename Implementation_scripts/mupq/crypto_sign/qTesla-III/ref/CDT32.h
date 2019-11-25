/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: CDT constants for the Gaussian sampler
**************************************************************************************/

#ifndef CDTSAMP
#define CDTSAMP

#include <stdint.h>
#include "params.h"


// Sigma = 10.2, 128-bit precision

#define CDT_ROWS 133
#define CDT_COLS 4

static const int32_t cdt_v[CDT_ROWS*CDT_COLS] = {
    0x00000000L, 0x00000000L, 0x00000000L, 0x00000000L, // 0
    0x05019F23L, 0x215AA886L, 0x266BD84AL, 0x1962528BL, // 1
    0x0EF8936EL, 0x23BFC791L, 0x31B19042L, 0x50351AA0L, // 2
    0x18CB03FCL, 0x0746C256L, 0x407022E8L, 0x334F94BBL, // 3
    0x2261C15EL, 0x4527ABF1L, 0x7CCF6441L, 0x00EF6D46L, // 4
    0x2BA749FEL, 0x4A371856L, 0x3A2CA997L, 0x5153CB0AL, // 5
    0x3488598AL, 0x0435B2D7L, 0x4DD990AEL, 0x0E7429C0L, // 6
    0x3CF45E22L, 0x01E1BF49L, 0x4CFF5AEEL, 0x26AE280CL, // 7
    0x44DDCECBL, 0x5BEB1ED9L, 0x2BD797BFL, 0x29192D65L, // 8
    0x4C3A608EL, 0x22F7BD95L, 0x7BAF5E4AL, 0x611E8A2EL, // 9
    0x530319A4L, 0x2AAB68C5L, 0x135B9B19L, 0x7D19FFA3L, // 10
    0x59344411L, 0x6FBA748BL, 0x4409DF71L, 0x76C2A4C2L, // 11
    0x5ECD42A3L, 0x12258E6CL, 0x70ABD8BFL, 0x33F8D6F8L, // 12
    0x63D04CBCL, 0x4B03A25AL, 0x17893AFDL, 0x00512D3CL, // 13
    0x68421661L, 0x279CDBF3L, 0x64BB398DL, 0x603BDA52L, // 14
    0x6C296A64L, 0x58D40125L, 0x5D5E3204L, 0x45948D03L, // 15
    0x6F8EBCDCL, 0x2CBC9B6CL, 0x078DBD24L, 0x11153742L, // 16
    0x727BBBA2L, 0x6464E481L, 0x6C03A4A4L, 0x4FBBF658L, // 17
    0x74FAE221L, 0x32614E4BL, 0x4B399625L, 0x5284D9C8L, // 18
    0x771714BEL, 0x64DE7817L, 0x5BAFF2C0L, 0x3A75B026L, // 19
    0x78DB474CL, 0x64906B4AL, 0x36C15D1AL, 0x49AAA0FCL, // 20
    0x7A5230BFL, 0x213597F2L, 0x3ECC4E7BL, 0x5FFE21CAL, // 21
    0x7B860D68L, 0x0DD17AC2L, 0x34CE2917L, 0x13D0DE15L, // 22
    0x7C806FFEL, 0x7068EFBDL, 0x603BDD00L, 0x24292429L, // 23
    0x7D4A20E9L, 0x2D5BC71BL, 0x470F64CEL, 0x63129FAFL, // 24
    0x7DEB0A96L, 0x00A6501CL, 0x4C461A13L, 0x790CAB86L, // 25
    0x7E6A3144L, 0x75C93242L, 0x16023571L, 0x06B7110BL, // 26
    0x7ECDB456L, 0x661A7E35L, 0x162E551AL, 0x75DB9DA9L, // 27
    0x7F1AD71FL, 0x20516B1FL, 0x5FF00AE2L, 0x43DFF254L, // 28
    0x7F560F41L, 0x3300DE7CL, 0x4B8F0799L, 0x5C3E4574L, // 29
    0x7F8316C3L, 0x1226EADBL, 0x51D0E0B1L, 0x5870949BL, // 30
    0x7FA5003CL, 0x3183FE96L, 0x56A3015DL, 0x5471CE29L, // 31
    0x7FBE4BCBL, 0x237FBE88L, 0x06124F61L, 0x189877D0L, // 32
    0x7FD0FBBEL, 0x4900A57BL, 0x1231A728L, 0x21713D51L, // 33
    0x7FDEA82DL, 0x4264689CL, 0x090BD52BL, 0x35B3EF58L, // 34
    0x7FE890F4L, 0x7F427C59L, 0x3FEA77A7L, 0x76B5CEC4L, // 35
    0x7FEFADC9L, 0x235461F2L, 0x76530FE7L, 0x458AFED6L, // 36
    0x7FF4BC39L, 0x47D62996L, 0x080C04AEL, 0x5578E91DL, // 37
    0x7FF84BA5L, 0x449EAC84L, 0x43D826FAL, 0x01AFCF15L, // 38
    0x7FFAC73EL, 0x68B27237L, 0x1032E3F9L, 0x63DED628L, // 39
    0x7FFC7E40L, 0x6CDCE391L, 0x74D2C6E0L, 0x56F439FAL, // 40
    0x7FFDAA93L, 0x2A0A579FL, 0x4E3FD638L, 0x555547D0L, // 41
    0x7FFE760EL, 0x7D0DA319L, 0x04AE9E8DL, 0x47F8B424L, // 42
    0x7FFEFE9CL, 0x00E6F118L, 0x5B12C69BL, 0x63045184L, // 43
    0x7FFF595EL, 0x1329625AL, 0x788CC79FL, 0x61B72C9CL, // 44
    0x7FFF951CL, 0x7C94755BL, 0x7F1054DFL, 0x57D6E351L, // 45
    0x7FFFBC11L, 0x0D63DD99L, 0x16E1DEEDL, 0x5FA47FD6L, // 46
    0x7FFFD538L, 0x56FC93F8L, 0x4BF6F51DL, 0x65D1F42FL, // 47
    0x7FFFE54FL, 0x26D25196L, 0x4AF51374L, 0x7A3F204DL, // 48
    0x7FFFEF80L, 0x25C7892BL, 0x5FC036B7L, 0x563D2EF5L, // 49
    0x7FFFF5E5L, 0x17797BB9L, 0x4AED0883L, 0x55F4708EL, // 50
    0x7FFFF9DEL, 0x2C7B5848L, 0x63C7FD09L, 0x7144559CL, // 51
    0x7FFFFC50L, 0x2F236C2DL, 0x04B38B5DL, 0x67E03136L, // 52
    0x7FFFFDCDL, 0x7C5C8A99L, 0x47780740L, 0x3CCCFB89L, // 53
    0x7FFFFEB4L, 0x2E1E4A11L, 0x366AC9FCL, 0x2F9E887CL, // 54
    0x7FFFFF3EL, 0x0FEBD46FL, 0x6BC1CE85L, 0x72F069E7L, // 55
    0x7FFFFF8FL, 0x5B6E489EL, 0x28751892L, 0x56C780B5L, // 56
    0x7FFFFFBFL, 0x495E9E5FL, 0x7EAA1ACBL, 0x351B085FL, // 57
    0x7FFFFFDBL, 0x3057607BL, 0x28E384A2L, 0x5C5256A0L, // 58
    0x7FFFFFEBL, 0x3035C5A3L, 0x15A78AB7L, 0x0FC670CFL, // 59
    0x7FFFFFF4L, 0x3F4D8780L, 0x66D50D33L, 0x63B5CB00L, // 60
    0x7FFFFFF9L, 0x5212DCE2L, 0x6CD045D5L, 0x07DDE51EL, // 61
    0x7FFFFFFCL, 0x425CE8A8L, 0x02F46379L, 0x69404141L, // 62
    0x7FFFFFFEL, 0x0E49947FL, 0x0E07EA75L, 0x3B58DBEAL, // 63
    0x7FFFFFFEL, 0x7E1F309BL, 0x2F0778A7L, 0x2D18E896L, // 64
    0x7FFFFFFFL, 0x3ADDCA91L, 0x5A24C395L, 0x56E970E7L, // 65
    0x7FFFFFFFL, 0x5B8B8969L, 0x73D05913L, 0x5979C1D5L, // 66
    0x7FFFFFFFL, 0x6CF50016L, 0x4970EBFFL, 0x7B2F8760L, // 67
    0x7FFFFFFFL, 0x7625525CL, 0x0AF78928L, 0x125CBC7EL, // 68
    0x7FFFFFFFL, 0x7AF2D44BL, 0x4619F7B3L, 0x318AF6FCL, // 69
    0x7FFFFFFFL, 0x7D6F51AFL, 0x18D38DD1L, 0x73C75828L, // 70
    0x7FFFFFFFL, 0x7EB5AA16L, 0x20B148BBL, 0x23D956F8L, // 71
    0x7FFFFFFFL, 0x7F5B63C8L, 0x7DDB2AD8L, 0x2773EA98L, // 72
    0x7FFFFFFFL, 0x7FAEBE67L, 0x62813FEFL, 0x732DBF3BL, // 73
    0x7FFFFFFFL, 0x7FD8444FL, 0x2E032276L, 0x5B2AFA19L, // 74
    0x7FFFFFFFL, 0x7FECC0FAL, 0x55F8D363L, 0x07F7A470L, // 75
    0x7FFFFFFFL, 0x7FF6C3E2L, 0x30CFCC16L, 0x21550403L, // 76
    0x7FFFFFFFL, 0x7FFB9C50L, 0x5FBBDCD2L, 0x06635365L, // 77
    0x7FFFFFFFL, 0x7FFDEEEFL, 0x0D5AA5B2L, 0x756EF80AL, // 78
    0x7FFFFFFFL, 0x7FFF093FL, 0x0AEFA9CBL, 0x71B85E69L, // 79
    0x7FFFFFFFL, 0x7FFF8E00L, 0x09F364F6L, 0x34A17AD9L, // 80
    0x7FFFFFFFL, 0x7FFFCBD4L, 0x1CD513A4L, 0x5CB1E269L, // 81
    0x7FFFFFFFL, 0x7FFFE859L, 0x400469ACL, 0x7530AE2DL, // 82
    0x7FFFFFFFL, 0x7FFFF561L, 0x1F898BDBL, 0x04826122L, // 83
    0x7FFFFFFFL, 0x7FFFFB46L, 0x5697977EL, 0x7C47A5FCL, // 84
    0x7FFFFFFFL, 0x7FFFFDEBL, 0x14C7AD1BL, 0x6DFCE35AL, // 85
    0x7FFFFFFFL, 0x7FFFFF17L, 0x38F29E00L, 0x15864C26L, // 86
    0x7FFFFFFFL, 0x7FFFFF9BL, 0x3B053D45L, 0x67D04FC5L, // 87
    0x7FFFFFFFL, 0x7FFFFFD4L, 0x790609C5L, 0x5E96D840L, // 88
    0x7FFFFFFFL, 0x7FFFFFEDL, 0x5E4DD5C7L, 0x7D8F388AL, // 89
    0x7FFFFFFFL, 0x7FFFFFF8L, 0x29C05963L, 0x0645E13DL, // 90
    0x7FFFFFFFL, 0x7FFFFFFCL, 0x672F2508L, 0x3FCB5C26L, // 91
    0x7FFFFFFFL, 0x7FFFFFFEL, 0x57757A13L, 0x73F0B7CEL, // 92
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x3B2C73A1L, 0x6BA2B500L, // 93
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x6428E338L, 0x5026719CL, // 94
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x74D85FA8L, 0x5D9E5301L, // 95
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7B92AB00L, 0x044C95FAL, // 96
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7E42777FL, 0x7055A4A6L, // 97
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F528317L, 0x1E611B26L, // 98
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FBD15BEL, 0x591E5FD1L, // 99
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FE66F66L, 0x4ED42CB5L, // 100
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF65357L, 0x3C11F581L, // 101
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFC5FA6L, 0x13A72C4CL, // 102
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFEA751L, 0x0087E173L, // 103
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF813CL, 0x68963485L, // 104
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFD1D2L, 0x6710A409L, // 105
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFEF56L, 0x56112414L, // 106
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFA0BL, 0x4B034EF2L, // 107
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFDE4L, 0x2CC83513L, // 108
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF42L, 0x631F9BC7L, // 109
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFBEL, 0x23B1C1ECL, // 110
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFE9L, 0x32023A0BL, // 111
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF8L, 0x25DDC591L, // 112
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFDL, 0x332A0006L, // 113
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x10BAC302L, // 114
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x5B278E34L, // 115
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x73EA444FL, // 116
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7C12EEC8L, // 117
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7EBC95AFL, // 118
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7F98EB43L, // 119
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FDF7528L, // 120
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FF5D2FBL, // 121
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFCD92AL, // 122
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFF087BL, // 123
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFB4CAL, // 124
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFE95DL, // 125
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFF940L, // 126
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFE02L, // 127
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFF6BL, // 128
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFD5L, // 129
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFF3L, // 130
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFCL, // 131
    0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, 0x7FFFFFFFL, // 132
}; // cdt_v

// memory requirements:
//     2048 samples: 43620 bytes
//     1024 samples: 23140 bytes
//      512 samples: 12900 bytes
//      256 samples:  7780 bytes
//      128 samples:  5220 bytes
//       64 samples:  3940 bytes
//       32 samples:  3300 bytes
// table alone: 2128 bytes

#endif 