# LITERATURE — DFA of Dipper: related work

Collected on 20 Oct 2026. Every number below was read from an abstract or an
ePrint/journal abstract page. **No full text was opened** (Springer and IEEE
Xplore pages were blocked). Before a number is cited in the paper, check it in
the full text. "[sup lost]" means a superscript was flattened in the page text
(e.g. "214" for 2^14): check the exponent in the PDF.

## Search log (20 Oct 2026)

| # | Source | Query | Result |
|---|---|---|---|
| 1 | WebSearch | `Dipper block cipher fault attack` | none on Dipper |
| 2 | WebSearch | `"Dipper" lightweight cipher Huseynli Imamverdiyev Alizadeh` | nothing relevant |
| 3 | WebSearch | `Dipper cipher MDPI Cryptography 2026 SPN ARX GIFT S-box` | nothing relevant |
| 4 | IACR ePrint search | `Dipper` | no results |
| 5 | OpenAlex search | `Dipper fault` | only unrelated hits |
| 6 | OpenAlex search | `Dipper block cipher` | only the design paper (doi:10.3390/cryptography10040052) |
| 7 | OpenAlex `cites:W7169875502` | works citing the Dipper paper | 0 citing works |
| 8 | WebSearch | `differential fault analysis GIFT block cipher nibble fault` | GIFT DFA papers (below) |
| 9 | WebSearch | `fault attack GIFT-COFB differential fault analysis` | ToFA, DNFA, Liu et al. |
| 10 | OpenAlex search | `fault attack GIFT cipher` | GIFT fault papers (below) |
| 11 | WebSearch | `Differential Fault Analysis on the families of SIMON and SPECK ciphers Tupsamudre` | ePrint 2014/267 |
| 12 | WebSearch / OpenAlex | `differential fault attack SPECK ...` | Huo et al. FDTC 2015, Nozaki & Yoshikawa 2018, Hou et al. TCHES 2019 |
| 13 | WebSearch / OpenAlex | `One-Bit Model Differential Fault Analysis Simon Family` | Grados Vasquez et al. FDTC 2015 |
| 14 | WebSearch / OpenAlex | `fault modular addition carry differential fault ARX` | LEA modular-addition DFA (Lim et al. 2020) |
| 15 | WebSearch | `differential fault analysis PRESENT single nibble fault` | Bagheri et al. 2013, Patranabis et al. FDTC 2017 |

**Dipper fault attacks found: NO.**

Dipper: A. Huseynli, Y. İmamverdiyev, J. Alizadeh, "Dipper: A Lightweight Hybrid
SPN–ARX Block Cipher", *Cryptography* (MDPI) 10(4):52, 2026,
doi:10.3390/cryptography10040052. The abstract covers MILP differential, linear,
impossible-differential and integral analysis, and nothing on fault attacks.

## A. DFA / fault attacks on GIFT

| Paper | Venue, year, DOI | Target | Fault model / location | Faults needed | Remaining key space / complexity | Source of number |
|---|---|---|---|---|---|---|
| Saha, Mukhopadhyay, Dasgupta, "ExpFault" | TCHES 2018(2):242–276, doi:10.13154/tches.v2018.i2.242-276; ePrint 2018/295 | GIFT (variant not in abstract) | TCHES: 1 nibble fault at start of round 25. ePrint revised: 2 nibble faults, rounds 25 and 23 | TCHES: 1; ePrint: 2 | TCHES: unique, complexity 2^14 [sup lost]; ePrint: 2^7.06 | both abstracts (they differ — state which version) |
| Patranabis et al., "SCADFA" | IEEE TC 68(10):1498–1510, 2019, doi:10.1109/TC.2019.2913644 | GIFT-128, PRESENT-80 | random nibble + side channel, last round key | best 4; avg 6–9 (GIFT-128) | not checked | abstract |
| Xie, Tian, Li, "Differential Fault Attack on GIFT" | Chinese J. Electronics 30(4):669–675, 2021, doi:10.1049/cje.2021.05.008 | GIFT-64, GIFT-128 | random nibble; round not in abstract | one round key: 20.24 (GIFT-64), 44.96 (GIFT-128) avg; master key: 31 / 32 avg | master key: 2^16 / 2^17 [sup lost] | abstract |
| Luo, Chen, Ming, Wu, "General DFA on PRESENT and GIFT with nibble" | IEEE Access 9:37697–37706, 2021, doi:10.1109/ACCESS.2021.3062665 | GIFT (variant not in abstract), PRESENT | nibble before S-layer, GIFT rounds 25–28 | GIFT: 64 | 2^11.91 computation [sup lost] | abstract |
| Gao, Zhang, Zhang, "DFA of GIFT based on byte model" | IEEE IoT J., 2024, doi:10.1109/JIOT.2024.3462412 | GIFT (variant not in abstract) | two byte-fault models | master key: theory 53.44 / 12.42; experiments ~79 / ~16 | not checked | abstract |
| Kundu, Ghosh, Aikata, Saha, "ToFA" | TCHES 2025(3):614–643, doi:10.46586/tches.v2025.i3.614-643; ePrint 2024/1927 | GIFT-64/128, BAKSHEESH | random byte (clock glitch); impossible-differential filtering | GIFT-128: 3 | GIFT-128 unique; GIFT-64: 2^32 [sup lost] with one fault level | abstract |
| Liu, Guan, Hu, "Fault attacks on AE modes for GIFT" | IET Inf. Sec. 16(1):51–63, 2021, doi:10.1049/ise2.12041 | GIFT, GIFT-COFB, ... | collision fault attack | GIFT: 64 | not checked | abstract |

## B. DFA on ARX ciphers

| Paper | Venue, year, DOI | Target | Fault model | Faults needed | Source |
|---|---|---|---|---|---|
| Tupsamudre, Bisht, Mukhopadhyay, "DFA on the families of SIMON and SPECK" | FDTC 2014, pp. 40–48, doi:10.1109/FDTC.2014.14; ePrint 2014/267 | SIMON, SPECK | SPECK: bit-flip, last round key | SPECK: n/3 on average (n-bit word) | abstract |
| Huo, Zhang, Feng, Wang, "Improved DFA on SPECK" | FDTC 2015, pp. 28–34, doi:10.1109/FDTC.2015.15 | SPECK | random fault; chosen-value fault | random: about 5–8 for last round key; chosen: 4 (except MSB) | abstract |
| Grados Vasquez, Borges, Portugal, Lara, "One-bit model DFA on Simon" | FDTC 2015, pp. 61–70, doi:10.1109/FDTC.2015.18 | SIMON96/96, 128/128 | one-bit faults | not in abstract | abstract |
| Nozaki, Yoshikawa, "SPECK vs round addition DFA" | AICCC 2018, doi:10.1145/3299819.3299837 | SPECK | round addition | 1 pair → 2 round keys | abstract |
| Hou, Breier, Zhang, Liu, "Fully automated DFA on software" | TCHES 2019(3):1–29, doi:10.46586/tches.v2019.i3.1-29 | SIMON, SPECK, PRIDE, AES | instruction-level | not in abstract | abstract |
| Lim, Lee, Han, "Improved DFA on LEA by algebraic modular addition" | IEEE Access 8:212794–212802, 2020, doi:10.1109/ACCESS.2020.3039805 | LEA | random word | not in abstract | abstract |

Note: the brief mentioned "Huang et al." for SPECK; no such paper was found. The
2015 SPECK DFA is by **Huo** et al.

## C. Context: PRESENT

| Paper | Venue, year, DOI | Fault model | Faults needed | Source |
|---|---|---|---|---|
| Bagheri, Ebrahimpour, Ghaedi, "New DFA on PRESENT" | EURASIP JASP 2013:145, doi:10.1186/1687-6180-2013-145 | single bit (last subkey); single nibble (master key) | ~48; ~18 avg | abstract |
| Patranabis, Breier, Mukhopadhyay, Bhasin, "One plus one is more than two" | FDTC 2017; ePrint 2017/1073 | nibble + power | best 4, avg ~7–8 | abstract |

## D. References added for the paper (21 Oct 2026)

Metadata of every entry in `paper/springer/refs.bib` was checked against Crossref
(api.crossref.org/works/<DOI>), with OpenAlex for full first names, Springer chapter pages for LNCS
volumes and the IACR ePrint page where relevant; the source URL is in a comment above each entry.
Added: Biham–Shamir 1997, Boneh–DeMillo–Lipton 1997, Piret–Quisquater 2003, Tunstall–Mukhopadhyay–Ali
2011, GIFT (Banik et al. 2017), PRESENT (Bogdanov et al. 2007), SIMON/SPECK (Beaulieu et al. 2015),
surveys (Bar-El et al. 2006, Barenghi et al. 2012), clock faults (Agoyan et al. 2010), optical faults
(Skorobogatov–Anderson 2002), countermeasures (Karaklajić et al. 2013, Gierlichs et al. 2012), and the GIFT /
ARX fault papers from sections A–C (ToFA, SCADFA, Gao et al., Liu et al., Lim et al., Patranabis et al. 2017).
Corrections: ExpFault DOI is 10.46586/tches.v2018.i2.242-276 (the 10.13154 DOI redirects); Liu et al. is
IET Inf. Secur. 16(1), 2022 (online 2021); Gao et al. 2024 is early access (no volume/pages yet).
These were used only for the statements they are cited for; their full texts were not opened.
