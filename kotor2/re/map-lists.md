# KMRP K1 → K2 (Steam Aspyr) map: lists, text, panels, popups, chargen

Scope: the 52 K1 sites in `k1_sites.tsv` whose function is CSWGuiListBox,
CAurGUIStringInternal, CSWGuiTextParams, CSWGuiPanel, CSWGuiMessageBox, CSWGuiToolTipPanel,
CSWGuiControl, CSWGuiButton, CSWGuiNavigable, CSWGuiStoreItemEntry, CSWGuiInGameSkillEntry,
CSWGuiSkillInfoBox, the CharGen/LevelUp panels and CSWGuiInGameSoloModeQuery. One row per
site is in `map-lists.tsv`: 44 confirmed, 5 likely, 3 not-needed. Every K2 byte string in that
file, and every extra site named below, was read back from the program by
`scripts/ListsBytes.java` (output `lists/bytes.txt`). It also checked whether each run starts
and ends on an instruction boundary.

Raw material is in `lists/`: `vt.txt` (vtables), `funcs_40.txt` (function lists), `d1..d5.txt`
(decompiles plus disassembly), `x1/x2.txt` (xrefs), `data1.txt` (constants), `sc_640.txt`.

## Facts that apply to every site

* **K2 code is built with frame pointers and without optimisation.** Every function opens with
  `55 8B EC` and keeps all its locals in `[ebp-N]`. So:
  * an entry detour takes `55 8BEC 83EC xx` (6 bytes), `55 8BEC 81EC imm32` (9 bytes) or the
    SEH form `55 8BEC 6AFF 68 imm32` (10 bytes; `55 8BEC 6AFF` is exactly 5);
  * K1 mid-function hooks that read `esp+N` slots, such as the list row rect at `esp+32`, have
    no esp-relative equivalent in K2. KPM parameter sources are registers, `esp±N` or
    constants (`KPatchCore/Models/Parameter.cs`), and they include `ebp`. A K2 hook should
    therefore pass `ebp` and read `[ebp-N]` in C++. The frame offsets for each site are
    given below.
* **Every embedded CSWGui control in K2 is 4 bytes larger, inserted early in the object.**
  The control flags are at +0x48 (K1 +0x44), the panel's focused control is at +0x20 (K1
  +0x1C), and the panel manager is at +0x1C (K1 +0x18). Offsets inside a container therefore
  drift by 4 for each control that precedes them. Two consequences: the listbox's fields sit
  0x10 above K1's, and the MessageBox's sub-controls sit 0xC to 0x2C above K1's.
* **Aspyr's own GUI scaling** (new compared with K1):
  * `StartLoadFromLayout` 0x40EE40 and `InitControl` 0x40F620 take extra flag arguments. When
    the flags are set they scale extents by `screen / (DAT_009F4390, DAT_009F4394)`, which
    hold 800 and 600 in the image's initialized .data. Those values are runtime variables, and
    nothing here establishes that they stay 800x600 at run time. With `DAT_00A1B9F0` set,
    `InitControl` also applies an aspect correction (0x40F9F0/0x40FA80/0x40FB40).
  * Panels load `*_p` layouts, for example `confirm_p`, `tooltip8X6_p` and `skillinfo_p`.
  * Text has its own scale, `0x479AB0`: `fs = 1 + 0.5 * floor(max(0, screenW - 1022) / 1024)`.
    The 0.5 is a float at 0x98C014, which ~50 places read, so it must not be patched. The
    result is cached in [0x9F5F64] and copied into each string's [+0x54] by 0x479B10. It
    depends on width only and moves in steps: 1.0 below 2046 px wide, 1.5 below 3070, 2.0
    below 4094. MessageBox, StoreItemEntry, SkillEntry and WrapStrings all multiply by it.
  * Panel recentring still uses the 640x480 design size: GetExtentAccountingForPanelOffset,
    HitCheckMouse and GetLocalMouseCoords.
* K2 HitCheckMouse and GetLocalMouseCoords read the screen size from globals
  `DAT_009F42A4`/`DAT_009F42A8` (initial 800/600). GetExtentAccountingForPanelOffset reads it
  from `manager+0x6C/+0x6E`.

## CSWGuiPanel (vtable 0x0098739C)

| K1 | K2 | notes |
| --- | --- | --- |
| HandleInputEvent 0x409E60 | 0x40EAA0 (slot 15) | `if ([this+0x20]) [this+0x20]->slot15(event,value)` |
| SetActiveControl 0x40A630 | 0x40EC00 (slot 2) | K1 hook +8 → K2 0x40EC09 (`mov eax,[ebp-8]; mov ecx,[eax+0x20]`, 6 bytes). Here ecx = panel and `[ebp+8]` = new control. K1 had them in edi/esi, so the detour's parameters must change. Consumed exit 0x40EC89 = `mov esp,ebp; pop ebp; ret 8` (verified) |
| StartLoadFromLayout 0x40A680 | 0x40EE40 | (CResRef*, scaleX, scaleY). `esp+4` is still the CResRef* the K1 detour reads |
| GetExtentAccountingForPanelOffset 0x40AA00 | 0x410020 | `SUB EAX,0x280` at 0x410071 and `SUB EAX,0x1E0` at 0x4100A0 |
| HitCheckMouse 0x40B690 | 0x40EAE0 (slot 16) | site at the same +0x37 offset as K1 |
| StopLoadFromLayout 0x40B8F0 | 0x40F5A0 | |
| InitControl 0x40B930 | 0x40F620 | 4 arguments (control, CExoString* tag, add, scale). K1 has 3 |
| GetLocalMouseCoords 0x40BA20 | 0x40FED0 | |
| Destructor 0x40CF70 | 0x40E860 | slot 0 is the deleting wrapper 0x87FDF0 |
| CenterPanel 0x40A600 (KMRP `kCentreOnScreen`) | 0x40EA00 | |

**Sign of the recentring operands.** K1 encodes these as `ADD EAX,-640`/`-480`, so its
original bytes are `80FD` and `20FE` and the patch writes −W. K2 encodes all six as
`SUB EAX,+640`/`+480` (`2D 80020000`, `2D E0010000`), so a K2 patch writes +W. Copying K1's
replacement bytes would add instead of subtract.

K2 CSWGuiPanel members:

| member | offset | evidence |
| --- | --- | --- |
| extent | +0x04..+0x10 | SetExtent 0x40E980 |
| manager | +0x1C | ctor 0x40E5A0 stores its argument; `[+0x1C]+0x6C/+0x6E` are the screen size |
| focused control | +0x20 | 0x40EAA0, 0x40EC00, 0x40E7B0 |
| control array / count | +0x24 / +0x28 | HitCheckMouse, Draw, InitControl |
| layout GFF | +0x30 | StartLoadFromLayout, StopLoadFromLayout |
| flags | +0x48 | bit 1 = centred, bit 2 = layout loaded, bits 0x10/0x20 = offset by screen, 0x40 = visible |
| alpha | +0x50 | |
| colour | +0x54..+0x5C | |
| border object | +0x60 | |

## CSWGuiListBox (vtable 0x00987D3C): the core of KMRP's list fixes

| K1 | K2 |
| --- | --- |
| OrganizeControls 0x41B140 | 0x41EA50 (1823 bytes, 13 callers) |
| OrganizeOversized 0x41A2D0 | 0x41F7F0 |
| shouldScroll 0x41A290 | 0x41E790 (19 callers) |
| AddControls 0x41C1D0 / AddControls_2 0x41C2C0 | 0x41FC30 (CExoArrayList*) / 0x41FD90 (ptr, count) |
| SetPadding 0x41C190 | 0x41E9D0 |
| SetExtent 0x41BF80 | 0x41D710 (slot 1) |
| HandleInputEvent 0x41CE20 | 0x41D940 (slot 15) |
| Load / LoadProtoItem | 0x41FFD0 / 0x420180 (strings PADDING, LEFTSCROLLBAR, PROTOITEM) |

K2 member offsets. Each is K1 + 0x10, except the item count, which became an int.

| member | K1 | K2 | evidence |
| --- | --- | --- | --- |
| content rect {l,t,w,h} | +0x28C | +0x29C/+0x2A0/+0x2A4/+0x2A8 | SetExtent 0x41D710 writes them |
| embedded scrollbar | +0x104 | +0x10C, its width at +0x118 | `add ecx,0x10C` before scrollbar calls; SetExtent |
| item array | +0x29C | +0x2AC | row loops |
| item count | +0x2C8 (word) | +0x2B0 (dword) | `mov ecx,[eax+0x2B0]` |
| item-rect array | +0x2A8 | +0x2B8 | measure loop `local*0x10 + [+0x2B8]` |
| row height (max of items) | +0x2B4 | +0x2C4 | measure loop, slot 13 (+0x34) of each item |
| scroll scale (float) | — | +0x2C8 | `fstp [ecx+0x2C8]` |
| flags | +0x2BC | +0x2CC | bit 3 = re-measure, 0x10 = LEFTSCROLLBAR, 0x100 = unequal, 0x200, 0x1000 |
| PADDING (byte) | +0x2C0 | +0x2D0 | SetPadding 0x41E9D0 performs the half-width/half-height check from the K1 doc |
| scroll position (word) | +0x2C2 | +0x2D2 | OrganizeOversized |
| visible rows (word) | +0x2C4 | +0x2D4 | `idiv` result |
| selected (word) | — | +0x2D6 | 0x41E870 |
| top visible (word) | — | +0x2D8 | OrganizeControls |

### OrganizeControls 0x41EA50: the logic matches K1

The decompile shows the same algorithm as the K1 doc. The row rect is a local at
`[ebp-0x30]` = {left, top, width, height}, the list is at `[ebp-0x54]`, and
`pitch = [ebp-0x14]`.

1. `pitch = PADDING + rowHeight` at 0x41EAF6, then the re-measure loop, then
   `pitch = PADDING + rowHeight` again at 0x41EC04, then `visible = height / pitch`. These are
   K1 0x41B1C4 and 0x41B26B. Each K2 site is an `ADD reg,[reg+0x2C4]` preceded by
   `movzx reg, byte PADDING`, so K1's `03`→`8B` patch works unchanged.
2. Fit tests: K2 calls `shouldScroll` 0x41E790 (`height < PADDING + rowHeight`) at 0x41ED90 and
   0x41EE07, where K1 has the test inline at 0x41B339 and 0x41B3AE. The one K2 byte is
   0x41E7A6 (`03`→`8B`). **It differs from K1**: 0x41E790 is shared with HandleInputEvent,
   with MessageBox FixMessageLabel (4 calls, in its auto-fit loop), and with 0x8B7A80, 0x8D6320,
   0x8DAEB0, 0x8DDC70, 0x41F980 and 0x420C00. Patching it changes the scroll decision for all
   of them; in K1 only OrganizeControls changed. Hence "likely". A narrower alternative would
   be to detour the two call sites.
3. Leftover distribution: `slack = height - PADDING - visible*pitch` at 0x41EF19..0x41EF3B. The
   `sub edx,eax` of PADDING is at 0x41EF29 (`2BD0`). No K1 site corresponds to it. With PADDING
   made horizontal only, it probably should go too; that is not verified.
   `extra = slack / visible` is at `[ebp-0x20]` and the remainder at `[ebp-0x8]`.
4. Width: `[+0x2A4] - 2*PADDING`, where `shl edx,1` at 0x41EF7D (`D1E2`) is K1 0x41B48C's
   `lea eax,[edi+edi]`. A NOP there gives width − PADDING.
5. Left and top: `mov [ebp-0x30],ecx` (= PADDING) and `mov dword [ebp-0x2C],0` at 0x41EF9D,
   10 bytes. This is K1 0x41B46D (gold v12 gutter stub: left = LEFTSCROLLBAR ? PADDING : 0,
   with LEFTSCROLLBAR = bit 0x10 of `[list+0x2CC]`).
6. Row-top chain: `top0 = -topVisible*pitch + PADDING`, where the `add edx,eax` at 0x41EFCF
   (`03D0`) adds PADDING. This is the second half of K1 0x41B48C (`xor edi,edi`). In K2 it is a
   separate 2-byte site.
7. Loop 1 covers rows above the first shown. Each row gets `top += pitch`, and the hook point
   is 0x41F013 (eax = row).
8. Loop 2 covers the rows shown: `rowH = rowHeight + extra` at 0x41F074 (`add edx,[ebp-0x20]`,
   K1 0x41B507). The first `remainder` rows get `top+1` (0x41F0C2) and `height+1` (0x41F0CB
   `83C001`, K1 0x41B52C/E). Then `top += PADDING + rowH` at 0x41F092..0x41F0A2, where
   0x41F09C is K1 0x41B553. The hook is at 0x41F0E9 (edx = row).
   **Difference from K1:** in K2 `rowH` ([ebp-4]) is both the height written into the row and
   the pitch, so the K1 NOP at 0x41F074 also takes the slack out of the row positions. K1 says
   its positions use a separate accumulator. Hence "likely". The K1 growth bug is present in K2
   in the same form: the re-measure loop takes the max of row heights that earlier passes
   inflated.
9. Loop 3 covers rows below; the hook is at 0x41F155 (edx = row).

The three row-hook sites are 6 bytes each: `mov [ebp-x],reg` + `lea r,[ebp-0x30]`. They come
before the `push`, so no stack change is stolen and they contain no relative operands. The
KmrpListRowK1 port needs (list = `[ebp-0x54]`, row = eax/edx/edx, rect = `ebp-0x30`).

### OrganizeOversized 0x41F7F0 (builder B)

This is the same arithmetic as K1 0x41A2D0. The rect is at `[ebp-0x14]` = {left, top, width,
height}, with width at 0x41F81C (`[+0x2A4] - 2*PADDING`, the `shl eax,1` at 0x41F80F) and
left = PADDING at 0x41F82F. For the top:

* bottom-anchored branch: `height - rowHeight - PADDING`, where `sub edx,eax` at 0x41F87D
  (`2BD0`) subtracts PADDING;
* scrolled branch: `ftol(...) + PADDING`, where `add eax,ecx` at 0x41F8D8 (`03C1`) adds it.

The TSV gives the 35-byte run 0x41F80F..0x41F831 (width through left) as the stub site; it
holds no relative operands. The two top sites are separate 2-byte NOP candidates and play the
part of the `edi` clearing in K1's v12 stub.

### AddControls 0x41FC30

The signature is `(CExoArrayList* rows, flag, flag, flag)`: `[rows]` = data and `[rows+4]` =
count. This matches what KmrpListAddRowsK1 reads at `esp+4`. Its K1 body hard-codes K1 row
vtables (0x755ED0, 0x7578A8) and the K1 row-height immediate (0x6ACB20, 0x6CD8D9). Those need
their K2 equivalents. The K2 vtables come from `classes.txt`: CSWGuiInGameSkillEntry
0x9A6CEC; CSWGuiSkillFlow is not looked up here.

## CAurGUIStringInternal (vtable 0x0098C0CC)

* WrapStrings is slot 19, 0x47AF30. Draw is slot 31, 0x47B500 (OpenGL).
* String members: char* at +0x14 (K1 +0x14), font holder at +0x18 (its slot +0x38 gives the
  font info, as K1), line arrays at +0x3C/+0x48 (counts +0x40/+0x4C), max width at +0x0C
  (word), K2 font scale at +0x54, last global scale at +0x5C.
* The short-string guards are the same as K1 0x45A3B7/0x45A3DC. K2 encodes each as `jge` over
  a `jmp exit`: 0x47B0B1 `7D07` and 0x47B0DA `7D05`. Changing them to `EB07`/`EB05` (or NOPing
  the 5-byte jmps at 0x47B0B3/0x47B0DC) removes them.
* The hard-break defect from K1 0x45A5E0 is present. At 0x47B312..0x47B324 the cursor
  `[ebp-0xC]` is decremented and compared with the *string* start `[this+0x14]`. The line
  start is `[ebp-0x14]`. Proposed K2 patch, an untested design:
  * `3B4814`→`3B4DEC` at 0x47B321 and `7519`→`7719` (ja 0x47B33F) at 0x47B324;
  * replace the 25-byte fall-through 0x47B326..0x47B33E (zero counts, jmp exit) with
    `mov edx,[ebp-0x14]; scan: cmp byte [edx],0; je +3; inc edx; jmp scan;
    mov [ebp-0xC],edx; jmp 0x47B276`;
  * 0x47B276 is the end-of-line path: it appends width `[ebp-0x2C]` and length
    `cursor - lineStart`, then exits through 0x47B4A1 → 0x47B0EF because the cursor is on NUL.

  The TSV run at 0x47B312 ends in a relative `jnz` and should not be used as stolen bytes.
* **Aspyr added a cap of 100 lines** (0x47B0E8 `[ebp-0x20]=0x64`). Past 100 it returns
  (0x47B10C..0x47B125), so the K1 crash (unbounded growth) cannot happen in K2. The
  oscillation would instead produce 100 duplicate lines. Removing the guards without the
  progress fix is therefore not a crash risk in K2, but still renders garbage.
* WrapStrings also strips leading `\n` itself: 0x47B131..0x47B165 appends a zero-width empty
  line for each one. This is the same blank first line K1 v13 removes at SetText.
* Draw prologue 0x47B500 is 9 bytes. Aspyr already multiplies glyph metrics by `[this+0x54]`
  (font scale). Whether KMRP's CAurFontInfo hook is still wanted depends on the K2 font
  approach. Marked likely: the function match is certain, the need is not.

## CSWGuiTextParams

* SetText is 0x416E30: CExoString assign 0x7337C0, `[+8]=-1`, then the owner check
  `[+0x50]`. The K1 trim point corresponds to 0x416E46 (`C74108FFFFFFFF`, ecx = this, string
  at +0).
* SetStrRef 0x416EA0 assigns the TLK string directly and does not go through SetText. The same
  holds in K1, where SetStrRef 0x415E50 is separate.
* Offsets: strref +0x08, colour +0x1C..+0x24, default colour +0x2C..+0x34, alignment bits
  +0x38 (low 6), font resref +0x3C, owner text object +0x50. They match K1's +0x50.

## CSWGuiButton, CSWGuiControl, CSWGuiNavigable

* Button::Initialize(rect, text, border, hilight) is slot 39, 0x419DC0. The slot 38 thunk
  0x419E90(rect, proto) calls it with proto+0x178/+0x84/+0xFC, mirroring K1 Initialize_2 →
  Initialize. At 0x419DE2 the bytes `8B400C 89410C` are byte-identical to the start of K1's
  hooked run. ecx is `this+4` (the extent) and eax is the source rect; the next instruction is
  `mov ecx,[ebp+0x10]`.
* Control::HandleInputEvent is slot 15, 0x418C50. Its event table is at +0x3C (data) and +0x40
  (count), with 12-byte entries {receiver, handler, event}; K1 has +0x38/+0x3C.
  CSWGuiControl::Destructor is 0x418640.
* Navigable::HandleInputEvent is slot 15, 0x4187B0. Move-to pointers: +0x60 up, +0x64 left,
  +0x68 down, +0x6C right; K1 has +0x5C..+0x68. Button::HandleInputEvent is 0x41A110.

## CSWGuiMessageBox (vtable 0x0099E6A4)

* Constructor 0x75AE40 loads `confirm_p`.
* FixMessageLabel 0x75C080 was rewritten by Aspyr, with the same intent as K1:
  * icon: when bit 0x10 of `[box+0x68]` is set, `height += fs*32`, `messageTop += fs*32` and
    `panelTop -= fs*16`. The doubles are at 0x99D798 (32.0) and 0x9946D0 (16.0). Both are
    shared with other code (17 and 19 readers), so patch the disp32 of the two `fmul` at
    0x75C12A and 0x75C13E (and of the 16.0 use at 0x75C152 if wanted), not the constants;
  * the K1 integer caps `cmp ecx,0x1B8` / `cmp eax,0x118` became doubles, 440.0 at 0x99E758
    and 280.0 at 0x99E750. Each has exactly 2 readers, both in this function (0x75C703,
    0x75C73A and 0x75C718, 0x75C7AD), so a data patch is safe. **In K2 both are multiplied by
    Aspyr's font scale**, so the effective caps are 440/280 times 1.0 to 2.0, not fixed;
  * the auto-fit loop condition is `shouldScroll(LB_MESSAGE) && (w < fs*440 || h < fs*280)`.
    It adds width 0x28 per step (left −0x14) when h > 0xA0, and height by the message row
    height. The loop stops on `shouldScroll`, so the 0x41E7A6 listbox patch also changes when
    this loop stops.
* Icon rect in the constructor: {0, 10, 0x20, 0x20}, as two imm32 at 0x75B0A0 and 0x75B0A7,
  then multiplied by the font scale (0x75B161, 0x75B172). K1 has one `mov eax,0x20`.
* End of FixMessageLabel: 0x75CA19 `mov ecx,[ebp-0x90]`, then `call CenterPanel`, then
  `pop esi; mov esp,ebp; pop ebp; ret`. The box is `[ebp-0x90]`; pass `ebp`.
* K2 offsets (K1 in brackets):

  | member | K2 offset | K1 offset |
  | --- | --- | --- |
  | icon | +0x1C0 | +0x1B4 |
  | BTN_OK | +0x308 | +0x2F4 |
  | BTN_CANCEL | +0x4D8 | +0x4B8 |
  | LB_MESSAGE | +0x6A8 | +0x67C |
  | message label | +0x78 | — |
  | icon flags | +0x68 | +0x64 |
  | button-shown flag | button + 0x48 bit 2 | button + 0x44 |
  | saved panel extent | +0x998 | — |
  | saved message extent | +0x9A8 | +0x970 (message top) |
  | unknown flag; when set, the box is centred on half the screen width (meaning a guess) | +0x9BC | — |

  `AddMessageLabel` (KMRP `kRebuildMessage`) is 0x75BF60.

## CSWGuiToolTipPanel: not needed

Constructor 0x75FDA0 always loads `tooltip8X6_p` with scale flags (1,1), and InitControl uses
`tooltip`. The K1 chain of width/height compares that left 1280-wide sizes with no layout
(0x627832..0x62785F) does not exist in K2.

## Rows: CSWGuiInGameSkillEntry, CSWGuiStoreItemEntry, CSWGuiSkillInfoBox

* SkillEntry::SetExtent is slot 1, 0x8A58E0. It returns early if width ≤ 0x2A, and Aspyr
  scales its icon squares by the font scale.
  * Part offsets: hex +0x1C0, hilight +0x238, icon +0x2B0, button parts +0x60/+0x148, text
    +0xD8. K1 has +0x1B4/+0x228/+0x29C and text +0xD0.
  * Hook 0x8A5AB9: ecx = text (row + 0xD8), eax = rect.
  * The row size is 0x328 in K2 (K1 0x310), from SkillInfoBox's vector-constructor stride.
* StoreItemEntry::SetExtent is slot 1, 0x8B0C30.
  * Icon 0x24 (36) × fs; the stack-count label is 0x15 (21) or 0x37 (55) wide and 0x13 tall,
    each × fs. Offsets come from doubles at 0x99EFA0 and 0x9A7768 × fs.
  * All the operands are imm32 (0x8B0C87, 0x8B0C8E, 0x8B0D58, 0x8B0D71, 0x8B0DC3), so K1's
    imm8 relocation stub is not needed. If KMRP wants its own scale instead of Aspyr's, those
    imm32s can be rewritten in place.
  * The K1 "inventory" row vtable (CSWGuiInGameItemEntry) was not mapped here.
* SkillInfoBox:
  * Constructor 0x89C5F0 (`skillinfo_p`). Members: LB_SKILLS +0x68 (K1 +0x64), LBL_MESSAGE
    +0x358 (K1 +0x344), BTN_OK +0x4A0 (K1 +0x484).
  * **20 rows** at +0x678, stride 0x328. K1 has 10 rows at +0x648, stride 0x310.
  * The fill, SetSkillList, is 0x89CB60. Hook 0x89CC21 comes after AddControls (0x89CC13) and
    the two pushes for `box->SetActiveControl(list,0)`; there eax = LB_SKILLS, and the box is
    `[ebp-0x24]`.

## Character generation, level-up, solo mode

All of these are vtable slot 15 with the K1 event codes. Each ends with `call 0x40EAA0`
(panel base) or, for solo mode, `0x75B8E0` (MessageBox base, since CSWGuiInGameSoloModeQuery
derives from CSWGuiMessageBox in K2: vtable slots 28–33 are identical). Aspyr added codes
0x1F6/0x1F7 to solo mode. The portrait screen also handles 0x35/0x36; whether K1 does was not checked. Entry bytes are
`55 8BEC 83EC xx`, so the hooks' stack parameters (`esp+4`, `esp+8`) are unchanged at entry.

## Blocking / open

* K1 vtable slot numbers were not available (no K1 exe). Every slot match above rests on K2
  slot behaviour plus code shape, strings and constants, not on K1 slot indices.
* Ports of KMRP C++ hook bodies need the K2 offsets above and K2 vtables. Every K1 vtable
  constant in K1RuntimeLayout.cpp, K1GrantedPopup.cpp and K1PopupFit.cpp must be replaced.
* Not established: whether DAT_009F4390/94 (800x600) change at run time, and how Aspyr's
  width-only font-scale steps interact with KMRP's height-based scale. This decides whether
  the message-box caps, the store label sizes and the Draw hook are wanted at all in K2.
