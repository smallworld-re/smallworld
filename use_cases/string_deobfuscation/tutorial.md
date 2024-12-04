# Harnessing to deobfuscate strings in malware

Malicious software will often encrypt or otherwise obfuscate its
strings. This makes manual reverse engineering in something like
Ghidra or IDA Pro much more annoying, as strings are not available for
viewing in the disassembly. Logging messages, window titles all appear
as jibberish. If possible, it is worthwhile, as precursor to reverse
engineering, to decrypt the strings offline and patch them back into
the binary.

In this tutorial, we will work with a binary that deobfuscates its
strings as it runs, and see how to use Smallworld to harness a subset
of the program's functions in order to output a file containing the
decrypted data, which can then be injected back into the binary for
manual reversing.

## Setup and Motivation

You should be able to create the (very simple, completely bogus, and
entirely harmless *malware* program `strdeobfus2` by running `make` in
this directory.  

```
(smallworld) tleek@leet:~/git/smallworld/use_cases/string_deobfuscation$ make
gcc -c -o _strdeobfus.o _strdeobfus.c  -D DEOBFS 
gcc -o _strdeobfus _strdeobfus.o
gcc -c -o strdeobfus.o _strdeobfus.c # -D DEOBFS 
gcc -o strdeobfus strdeobfus.o
./_strdeobfus
string1: [wTEGA.MW.FMC..}KQ.NQWP.SKJ.P.FAHMARA.LKS.REWPH]..LQCAH]..IMJ@.FKCCHMJCH].FMC.MP.MW..m.IAEJ..]KQ.IE].PLMJO.MP.W.E.HKJC.SE].@KSJ.PLA.VKE@.PK.PLA.GLAIMWP.W..FQP.PLEP.W.NQWP.TAEJQPW.PK.WTEGA.$]
string2: [e.PKSAH...pLA.lMPGLLMOAV.W.cQM@A.PK.PLA.cEHE\]y.WE]W..MW.EFKQP.PLA.IKWP.IEWWMRAH].QWABQH.PLMJC.EJ.MJPAVWPAHHEV.LMPGLLMOAV.GEJ.LERA..tEVPH].MP.LEW.CVAEP.TVEGPMGEH.REHQA..}KQ.GEJ.SVET.MP.EVKQJ@.]KQ.BKV.SEVIPL.EW.]KQ.FKQJ@.EGVKWW.PLA.GKH@.IKKJW.KB.nECHEJ.fAPE..]KQ.GEJ.HMA.KJ.MP.KJ.PLA.FVMHHMEJP.IEVFHA.WEJ@A@.FAEGLAW.KB.wEJPVECMJQW.r..MJLEHMJC.PLA.LAE@].WAE.RETKVW..]KQ.GEJ.WHAAT.QJ@AV.MP.FAJAEPL.PLA.WPEVW.SLMGL.WLMJA.WK.VA@H].KJ.PLA.@AWAVP.SKVH@.KB.oEOVEBKKJ..QWA.MP.PK.WEMH.E.IMJMVEBP.@KSJ.PLA.WHKS.LAER].vMRAV.iKPL..SAP.MP.BKV.QWA.MJ.LEJ@.PK.LEJ@.GKIFEP..SVET.MP.VKQJ@.]KQV.LAE@.PK.SEV@.KBB.JK\MKQW.BQIAW.KV.ERKM@.PLA.CE^A.KB.PLA.vERAJKQW.fQCFHEPPAV.fAEWP.KB.pVEEH..WQGL.E.IMJ@.FKCCMJCH].WPQTM@.EJMIEH..MP.EWWQIAW.PLEP.MB.]KQ.GEJ.P.WAA.MP..MP.GEJ.P.WAA.]KQ...]KQ.GEJ.SERA.]KQV.PKSAH.MJ.AIAVCAJGMAW.EW.E.@MWPVAWW.WMCJEH..EJ@.KB.GKQVWA.@V].]KQVWAHB.KBB.SMPL.MP.MB.MP.WPMHH.WAAIW.PK.FA.GHAEJ.AJKQCL.$]
python ./encrypt_strings.py
found enc_string1 = [b'$wTEGA\x04MW\x04FMC\n\x04}KQ\x04NQWP\x04SKJ\x03P\x04FAHMARA\x04LKS\x04REWPH]\x08\x04LQCAH]\x08\x04IMJ@\tFKCCHMJCH]\x04FMC\x04MP\x04MW\n\x04m\x04IAEJ\x08\x04]KQ\x04IE]\x04PLMJO\x04MP\x03W\x04E\x04HKJC\x04SE]\x04@KSJ\x04PLA\x04VKE@\x04PK\x04PLA\x04GLAIMWP\x03W\x08\x04FQP\x04PLEP\x03W\x04NQWP\x04TAEJQPW\x04PK\x04WTEGA\n$']
found enc_string2 = [b'$e\x04PKSAH\x08\x04\x7fpLA\x04lMPGLLMOAV\x03W\x04cQM@A\x04PK\x04PLA\x04cEHE\\]y\x04WE]W\x08\x04MW\x04EFKQP\x04PLA\x04IKWP\x04IEWWMRAH]\x04QWABQH\x04PLMJC\x04EJ\x04MJPAVWPAHHEV\x04LMPGLLMOAV\x04GEJ\x04LERA\n\x04tEVPH]\x04MP\x04LEW\x04CVAEP\x04TVEGPMGEH\x04REHQA\n\x04}KQ\x04GEJ\x04SVET\x04MP\x04EVKQJ@\x04]KQ\x04BKV\x04SEVIPL\x04EW\x04]KQ\x04FKQJ@\x04EGVKWW\x04PLA\x04GKH@\x04IKKJW\x04KB\x04nECHEJ\x04fAPE\x1f\x04]KQ\x04GEJ\x04HMA\x04KJ\x04MP\x04KJ\x04PLA\x04FVMHHMEJP\x04IEVFHA\tWEJ@A@\x04FAEGLAW\x04KB\x04wEJPVECMJQW\x04r\x08\x04MJLEHMJC\x04PLA\x04LAE@]\x04WAE\x04RETKVW\x1f\x04]KQ\x04GEJ\x04WHAAT\x04QJ@AV\x04MP\x04FAJAEPL\x04PLA\x04WPEVW\x04SLMGL\x04WLMJA\x04WK\x04VA@H]\x04KJ\x04PLA\x04@AWAVP\x04SKVH@\x04KB\x04oEOVEBKKJ\x1f\x04QWA\x04MP\x04PK\x04WEMH\x04E\x04IMJMVEBP\x04@KSJ\x04PLA\x04WHKS\x04LAER]\x04vMRAV\x04iKPL\x1f\x04SAP\x04MP\x04BKV\x04QWA\x04MJ\x04LEJ@\tPK\tLEJ@\tGKIFEP\x1f\x04SVET\x04MP\x04VKQJ@\x04]KQV\x04LAE@\x04PK\x04SEV@\x04KBB\x04JK\\MKQW\x04BQIAW\x04KV\x04ERKM@\x04PLA\x04CE^A\x04KB\x04PLA\x04vERAJKQW\x04fQCFHEPPAV\x04fAEWP\x04KB\x04pVEEH\x04\x0cWQGL\x04E\x04IMJ@\tFKCCMJCH]\x04WPQTM@\x04EJMIEH\x08\x04MP\x04EWWQIAW\x04PLEP\x04MB\x04]KQ\x04GEJ\x03P\x04WAA\x04MP\x08\x04MP\x04GEJ\x03P\x04WAA\x04]KQ\r\x1f\x04]KQ\x04GEJ\x04SERA\x04]KQV\x04PKSAH\x04MJ\x04AIAVCAJGMAW\x04EW\x04E\x04@MWPVAWW\x04WMCJEH\x08\x04EJ@\x04KB\x04GKQVWA\x04@V]\x04]KQVWAHB\x04KBB\x04SMPL\x04MP\x04MB\x04MP\x04WPMHH\x04WAAIW\x04PK\x04FA\x04GHAEJ\x04AJKQCL\n$']
Found $-delimited strings in data section: (32, 220, 224, 1123)
wrote strdeobfus2, which has encrypted strings in its data section
```

At this point, you should have a program `strdeobfus2` which has obfuscated strings in it. 
Here's let's verify that with the `strings` command.

```
(smallworld) tleek@leet:~/git/smallworld/use_cases/string_deobfuscation$ strings ./strdeobfus2
/lib64/ld-linux-x86-64.so.2
GLIBC_2.2.5
GLIBC_2.3
GLIBC_2.34
GLIBC_2.4
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
__ctype_b_loc
__cxa_finalize
__gmon_start__
__libc_start_main
__stack_chk_fail
fclose
fopen
fwrite
libc.so.6
printf
putchar
puts
strlen
PTE1
u+UH
%s: [
string1
string2
new_strings
:*3$"
$wTEGA
NQWP
FAHMARA
REWPH]
LQCAH]
IMJ@    FKCCHMJCH]
IAEJ
PLMJO
HKJC
@KSJ
VKE@
GLAIMWP
PLEP
NQWP
TAEJQPW
WTEGA
PKSAH
lMPGLLMOAV
cQM@A
cEHE\]y
WE]W
EFKQP
IKWP
IEWWMRAH]
QWABQH
PLMJC
...
```


The last several lines (and many more which are elided away here) are
the encrypted strings.  Well, I guess that isn't entirely apparent
(though I know it to be true). What is apparent, is that if we run
this program some very readable and funny strings emerge.

```
(smallworld) tleek@leet:~/git/smallworld/use_cases/string_deobfuscation$ ./strdeobfus2 
string1: [Space is big. You just won't believe how vastly, hugely, mind-bogglingly big it is. I mean, you may think it's a long way down the road to the chemist's, but that's just peanuts to space.$]
string2: [A towel, [The Hitchhiker's Guide to the Galaxy] says, is about the most massively useful thing an interstellar hitchhiker can have. Partly it has great practical value. You can wrap it around you for warmth as you bound across the cold moons of Jaglan Beta; you can lie on it on the brilliant marble-sanded beaches of Santraginus V, inhaling the heady sea vapors; you can sleep under it beneath the stars which shine so redly on the desert world of Kakrafoon; use it to sail a miniraft down the slow heavy River Moth; wet it for use in hand-to-hand-combat; wrap it round your head to ward off noxious fumes or avoid the gaze of the Ravenous Bugblatter Beast of Traal (such a mind-boggingly stupid animal, it assumes that if you can't see it, it can't see you); you can wave your towel in emergencies as a distress signal, and of course dry yourself off with it if it still seems to be clean enough.$]
```

Where do those strings come from? If we open the binary `strdeobfuz2`
in Ghidra we can see `
