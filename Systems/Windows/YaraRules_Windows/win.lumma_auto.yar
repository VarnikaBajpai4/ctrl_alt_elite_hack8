rule win_lumma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.lumma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 53 ff767c ff7678 ff7644 }
            // n = 4, score = 1100
            //   53                   | push                ebx
            //   ff767c               | push                dword ptr [esi + 0x7c]
            //   ff7678               | push                dword ptr [esi + 0x78]
            //   ff7644               | push                dword ptr [esi + 0x44]

        $sequence_1 = { ff7608 ff7044 ff503c 83c414 }
            // n = 4, score = 1100
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff7044               | push                dword ptr [eax + 0x44]
            //   ff503c               | call                dword ptr [eax + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_2 = { ff7134 ff5130 83c410 85c0 }
            // n = 4, score = 1100
            //   ff7134               | push                dword ptr [ecx + 0x34]
            //   ff5130               | call                dword ptr [ecx + 0x30]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax

        $sequence_3 = { e8???????? 833800 740a e8???????? 833822 }
            // n = 5, score = 1000
            //   e8????????           |                     
            //   833800               | cmp                 dword ptr [eax], 0
            //   740a                 | je                  0xc
            //   e8????????           |                     
            //   833822               | cmp                 dword ptr [eax], 0x22

        $sequence_4 = { 894610 8b461c c1e002 50 }
            // n = 4, score = 1000
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   c1e002               | shl                 eax, 2
            //   50                   | push                eax

        $sequence_5 = { ff770c ff37 ff7134 ff5130 }
            // n = 4, score = 1000
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   ff37                 | push                dword ptr [edi]
            //   ff7134               | push                dword ptr [ecx + 0x34]
            //   ff5130               | call                dword ptr [ecx + 0x30]

        $sequence_6 = { 83c410 85c0 7407 8907 }
            // n = 4, score = 1000
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   8907                 | mov                 dword ptr [edi], eax

        $sequence_7 = { ff7678 ff7644 ff563c 83c414 }
            // n = 4, score = 1000
            //   ff7678               | push                dword ptr [esi + 0x78]
            //   ff7644               | push                dword ptr [esi + 0x44]
            //   ff563c               | call                dword ptr [esi + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_8 = { 017e78 83567c00 017e68 83566c00 }
            // n = 4, score = 800
            //   017e78               | add                 dword ptr [esi + 0x78], edi
            //   83567c00             | adc                 dword ptr [esi + 0x7c], 0
            //   017e68               | add                 dword ptr [esi + 0x68], edi
            //   83566c00             | adc                 dword ptr [esi + 0x6c], 0

        $sequence_9 = { 83c40c 6a02 6804010000 e8???????? }
            // n = 4, score = 800
            //   83c40c               | add                 esp, 0xc
            //   6a02                 | push                2
            //   6804010000           | push                0x104
            //   e8????????           |                     

        $sequence_10 = { 8d8672920300 ff7604 57 50 }
            // n = 4, score = 800
            //   8d8672920300         | lea                 eax, [esi + 0x39272]
            //   ff7604               | push                dword ptr [esi + 4]
            //   57                   | push                edi
            //   50                   | push                eax

        $sequence_11 = { ff7034 ff5030 83c410 85c0 }
            // n = 4, score = 800
            //   ff7034               | push                dword ptr [eax + 0x34]
            //   ff5030               | call                dword ptr [eax + 0x30]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax

        $sequence_12 = { 41 5a cb 55 89e5 }
            // n = 5, score = 700
            //   41                   | inc                 ecx
            //   5a                   | pop                 edx
            //   cb                   | retf                
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp

        $sequence_13 = { e8???????? 83c40c 017e58 297e5c 03be8c000000 }
            // n = 5, score = 700
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   017e58               | add                 dword ptr [esi + 0x58], edi
            //   297e5c               | sub                 dword ptr [esi + 0x5c], edi
            //   03be8c000000         | add                 edi, dword ptr [esi + 0x8c]

        $sequence_14 = { 59 41 58 5a 59 41 5a }
            // n = 7, score = 700
            //   59                   | pop                 ecx
            //   41                   | inc                 ecx
            //   58                   | pop                 eax
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx
            //   41                   | inc                 ecx
            //   5a                   | pop                 edx

        $sequence_15 = { f6460a04 7507 837e3c30 0f92c0 }
            // n = 4, score = 700
            //   f6460a04             | test                byte ptr [esi + 0xa], 4
            //   7507                 | jne                 9
            //   837e3c30             | cmp                 dword ptr [esi + 0x3c], 0x30
            //   0f92c0               | setb                al

        $sequence_16 = { c70000000000 85c9 7406 c70100000000 c7466cfeffffff b8feffffff 5e }
            // n = 7, score = 700
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   c7466cfeffffff       | mov                 dword ptr [esi + 0x6c], 0xfffffffe
            //   b8feffffff           | mov                 eax, 0xfffffffe
            //   5e                   | pop                 esi

        $sequence_17 = { e8???????? 83c40c 019e8c000000 39ef }
            // n = 4, score = 700
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   019e8c000000         | add                 dword ptr [esi + 0x8c], ebx
            //   39ef                 | cmp                 edi, ebp

    condition:
        7 of them and filesize < 1115136
}