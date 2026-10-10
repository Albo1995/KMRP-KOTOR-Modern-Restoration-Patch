# KMRP K1 -> K2 (Steam Aspyr) map: screen, movie, resolution, input, map, dialogue group

Target: `swkotor2.exe` 6,588,416 bytes, SHA-256 `6A522E71…BBFFEF`, image base 0x400000.
Rows: `map-screen.tsv` (74 K1 sites of this group; duplicate VAs from different hook
files keep one row each). New K2 names: `k2_names-screen.tsv`.

| status | rows |
| --- | --- |
| confirmed | 33 |
| likely | 13 |
| not-needed | 22 |
| not-found | 6 |

All addresses below are K2 Steam VAs unless marked K1. Nothing was patched or run;
this is static analysis in Ghidra (project copy `screen`). Scripts added:
`scripts/ScreenFind.java` (strings, imports, immediates, byte patterns, function
lists, dword dumps), `scripts/ScreenDis.java` (N instructions with bytes; `*` marks
branch/call targets), `scripts/ScreenCallsOn.java` (calls made through a global).

## 0. Things that change how every K1 hook ports

* **The Steam build is unoptimised (/Od-style).** Every function has a `push ebp /
  mov ebp,esp` frame, `this` is spilled to `[ebp-N]` immediately and reloaded before
  each use, and every value goes through a stack slot. KMRP's K1 hooks that read
  `this`/arguments from ESI/EDI/EBX/EBP-as-data **cannot take the same register
  sources in K2**. The TSV evidence column names where each value lives at the K2
  site (`[ebp-0xE0]`, `[ebp+8]`…). KPM supports `source = "ebp"` (used by
  K2AspyrMapAspectFix, ExpandedKeyboardControl K2-GOG), so handlers must take EBP and
  read the frame.
* Entry stolen bytes are `55 8B EC …`. Where the third instruction is `push -1`
  (`6A FF`) the 5-byte prologue `55 8BEC 6AFF` is a clean steal (the following
  `push imm32` is the SEH handler address and is position-independent anyway).
* Many K1 *immediate operands* (640/480, marker sizes, 0.428571) are **doubles in
  .rdata** in K2, often shared by unrelated code. Patching the double changes every
  reader; the TSV lists readers for the shared ones.

## 1. How Aspyr's K2 chooses, enumerates and scales resolutions

**Enumeration** (`CSWGuiOptionsResolution::Constructor` 0x7D8540, the BTN_RESOLUTION
list): walks `EnumDisplaySettingsA` from mode 0 and adds a row when
`bpp == 32` && `ModeFitsDesktop` (0x93C9C0: w ≤ desktop w && h ≤ desktop h, desktop
from `GetDesktopWindow/GetWindowRect`, cached 0xA80D90/0xA80D8C) && (`ModeMeetsMinimum`
0x93CA00: w ≥ 1024 && h ≥ 720 **or** the mode equals the desktop size) && refresh ≥ 60
(w < 2000) or ≥ 30 (w ≥ 2000). Rows are `"%d x %d"` or `"%d x %d @ %d Hz"` when the
mode reports a refresh; duplicates (same string) are deleted. Row `custom_value`
(`+0x5C`) is the EnumDisplaySettings index, as in K1. No `(stretched)` variant exists
on Windows (that is Linux-shim only, KPM K2AspyrWindowingFixes).

**Validity / startup**: there is no K1-style `IsValidResolution` list.
`ReadVideoModeSettings` 0x78A7A0 reads `Width/Height/RefreshRate` from
`.\swkotor2.ini [Graphics Options]`; if missing or < 1024x720 it either picks the
largest desktop-fitting mode (when `0xA13C30`, first run) or 1024x768; then
`ModeFitsDesktop && ModeIsSupported` (0x93CA30, returns 1) else 1024x768; refresh
< 60 is raised to 60 below 2000 px. `ReadAndSetVideoMode` 0x78A630 maps that to a mode
index (fallback nearest of 1024x768x32@60 via 0x78DF40 → 0x93CA40) and calls
`SetVideoMode`. **Consequence for KMRP:** sizes below 1024x720 (800x600, 1024x600,
1280x720 is fine) are never offered or accepted; K1's 800/600 operand patches have no
counterpart and are not needed for large sizes.

**Switching**: row click → `OnResolutionChosen` 0x7D9280: `CClientExoApp::SetVideoMode`
0x73FBD0 → `CClientExoAppInternal::SetVideoMode` 0x78DBF0 (same steps as K1 0x5F1830:
`[this+0x1A0]` current mode, globals `screenWidth 0x9F42A4 / screenHeight 0x9F42A8 /
bpp 0x9F42B0 / refresh 0x9F42AC`, `ReInitAurora` 0x409750(w,h,bpp,fs,1),
`GuiManager->SetSize` 0x411A80, main menu `[+0x280]`, load screen `[+0x278]` rebuilt,
`CGuiInGame::ResetInterfaceForSize` 0x7CFCA0 when `[+0x40]`), then ini write, then
two option panels rebuilt, then **Aspyr's `CSWGuiManager::RescalePanels` 0x412400**:
every panel in the manager's lists (+0x88, +0x94) and the eight in-game tab panels is
re-extented by `newW/panel.w`, `newH/panel.h` and every child control likewise —
i.e. a proportional stretch of live panels. On closing the dialog (events 0x28/0x2E,
`HandleInputEvent` 0x7D8FF0) a second `ReInitAurora` is done when `[this+0x840]`
(VBO ini keys re-read).

**GUI scaling at load (Aspyr)**: design size is the constant pair `0x9F4390 = 800`,
`0x9F4394 = 600` (never written). `CSWGuiPanel::StartLoadFromLayout` 0x40EE40 and
`CSWGuiPanel::InitControl` 0x40F620 (when its scale argument is set) multiply every
EXTENT by `viewport_w/800`, `viewport_h/600` (manager `+0x6C/+0x6E`) and set panel flag
bit0 of `+0x48`. With `0xA1B9F0` set (the HUD constructor sets it) InitControl also
re-projects control rects to keep a 4:3 (`0x987488 = 1.3333`) look on wider screens.
So **K2 already scales the whole GUI**, non-uniformly (stretched) except the HUD.
Other Aspyr pieces relevant here:
* `GetGuiScale` 0x479AB0 = 1 + floor(max(0, screenW−1022)/1024)·0.5 (1.0 / 1.5 / 2.0 …,
  steps at 2046 and 3070 px) — multiplies map markers, the map arrow, dialogue reply
  height (100·scale), some HUD text.
* `CSWGuiManager::Draw` 0x4113A0 scissor-clears black pillarbox bars when
  `W/H > 1.3333` in one mode (0x73FFA0 == 0 && 0x7AB800 == 2).
* In-game tab panels are created on demand and destroyed on leaving
  (`CGuiInGame::SetActiveTabPanel` 0x7D0760) unless `0xA10760` pre-creates them, so
  the K1 "map keeps the first size's surfaces" fault (resolution-switch.md §7) does
  not arise for the lazily created map.
* Movies always re-init at the running size (`ChangeResolutionForMovie` 0x40BE50).

## 2. Per function

### Movies — `CExoMoviePlayerInternal` (no RTTI; found by `SWMovieWindow` and Bink imports)
Layout identical to K1: `+0x14` interrupted, `+0x24` shutting_down, `+0x30`
movie_playing, `+0x48` HBINK, `+0x4C` HBINKBUFFER, `+0x50` HWND, `+0x84/+0x88`
dest x/y; new `+0x60`, `+0x64` (preloaded-Bink flag). Global movie HWND 0xA1B9E8,
class-registered flag 0xA1B9EC, main window 0xA1B484.
* InitializeMovie 0x40CC70: window over the main client rect (GetWindowInfo), style
  `0x90000000` then SetWindowLong `0x82000000`, `SetWindowPos(HWND_TOPMOST…)`.
  **Still width-only scale** (`clientW/movieW` applied to both dims) — K1 bug present,
  so the `.kmv`-style aspect fit is needed (site 0x40D218, resume 0x40D2F3).
  hbrBackground still NULL (grey flash fix still relevant).
* PlayMovieLoop 0x40D6F0: per-iteration hook at the loop condition 0x40D74F
  (this = `[ebp-0xE0]`). Aspyr's loop polls `CExoInput::GetEvents` and skips on input
  events 0x10/0x11/0x4D/0x4E (escape/space-like), unlike K1.
* Wndproc 0x40C4A0: same switch; Space is not handled (only Esc in WM_KEYDOWN,
  Alt+F4 / Alt+Enter in WM_SYSKEYDOWN, mouse up cancels); Aspyr adds 0x407/0x408 posted
  messages (0x408 → `RepositionMovieWindow` 0x40DD10).
* K1 movie-mode operands (0x403D6C/78, 0x5F5B3B): **not needed** — K2 uses the
  running size.

### `CSWGuiManager` (no RTTI; found via callers/structure; layout = K1)
`+0/+4` mouse x/y, `+0x8` mouse-over control, `+0x10` captured control, `+0x1C`
flags, `+0x20/+0x24` 3D cursor objects, `+0x3C` tooltip, `+0x6C/+0x6E` viewport w/h
(shorts), `+0x7C` object freed by SetSize, `+0x88/+0x8C` panels, `+0x94/+0x98` modal
panels. SetSize 0x411A80, Update 0x411870 (per-frame, calls panel slot 14), Draw
0x4113A0, HandleMouseMove 0x412C00, ReloadToolTipPanel 0x414090, RescalePanels
0x412400 (Aspyr). GUI_MANAGER_PTR 0xA1B49C (KPM DB) = `CClientExoAppInternal+0x274`
(0x73FEA0 returns it).

### Resolution options — `CSWGuiOptionsResolution` (RTTI 0x9A1CBC)
`+0x68` LBL_RESOLUTION, `+0x1B0` LB_RESOLUTIONS, `+0x4A0` BTN_OK, `+0x670`
BTN_CANCEL, `+0x840` "re-init on close" flag. HandleInputEvent slot 15 0x7D8FF0. In
K1 `0x27` (A/confirm) reaches HandleInputEvent and `ResolveResolutionConfirmK1` turns
A-on-Cancel into B; in K2 0x27 handlers are bound per control (`0x418AF0(0x27, …)`:
rows → 0x7D9280, Cancel → 0x762E90), so the entry hook still sees events but the
K1 rewrite logic must be re-checked against K2's routing.

### Input / controller
* `CExoInputInternal::GetEvents` 0x72C7E0 (assert string). Keyboard capture site
  0x72CB63 is byte-identical to KPM ExpandedKeyboardControl's K2-GOG hook (record in
  EAX, device index `[ebp-0x10]`). K2 also has DirectInput8 joystick support built in
  (`DirectInput8Create` via 0x93B3B0) and no XInput import, so KMRP's XInput layer is
  still meaningful.
* `CClientExoAppInternal::ProcessInput` 0x7AC470, `MainLoop` 0x781BE0, UpdateCamera
  candidate 0x78C350; camera site 0x783148 (likely).
* `CSWPlayerControlCamRelative::Control` = vtable slot 10 0x865830 (K1 layout
  `+0x10` up_down, `+0x14` left_right, `+0x18` walking). Normalize call 0x865B3E.
* `CSWGuiMainInterface` (RTTI 0x99DCC4): ctor 0x747210, dtor 0x74AD90, Update
  slot 14 0x74C320, Draw slot 13 0x74B3F0, HIE slot 15 0x7469F0, DrawMap 0x750790.
  KPM-GOG offsets for the minimap (`+0x5AB4` control, `+0x5D54/+0x5D58` scaled size)
  hold in Steam too (`+0x5D44..+0x5D50` viewport rect).

### Rumble — `CClientExoAppInternal`
Offsets identical to K1: `+0x340` patterns (stride 0x24), `+0x344` count,
`+0x34C/+0x350` active queue. Play 0x79D3F0, Stop 0x79D4E0, Update 0x79D550 (push
0x927C0 at 0x79D6B4; magnitudes are float stack args, not EAX/ECX), LookUpAndPerform
0x79F010. Footstep/VFX 2DA pointers at `[0xA1B4D0]+0x130 → +0x5C / +0x1C`.

### Combat events
`CSWCCreature::RegisterCallbacks` 0x77F240 registers "hit" → HitEvent 0x7631D0,
"Contact" → 0x763110 → `ShowLightSaberContactVisual` 0x771F70, "HitParry" → 0x763160.
`CreateMuzzleFlash` candidate 0x8EE4C0. AnimationParry and
ResolveCreaturePoweredAnimations were not located (no anchor without the K1 binary).

### Memory safety (texture buckets, grass)
Not located. KPM's TextureBucketSafety / GrassMemorySafety are K1-only; K2 render
bucket code sits near Scene::DoGobBuckets (0x468112, KPM Max Lights) but
AurTextureGetMaxTexID / AddPartToMeshBuckets / CAurTriangleBin have no string or
constant anchor I could tie to the K1 shapes. Treat as open.

### Area map — `CSWGuiInGameMap` (RTTI 0x9A67EC), `CSWGuiMapHider` (0x9A68B4)
K2 map domain is **588x294** (world→map 0x5F7060 range-checks 0x24C/0x126); canvas
(`+0x13B8`, image) and marker overlay (`+0x1160`, CSWGuiMapHider) are **both**
`ftol(vw/800·588) × ftol(vh/600·294)` (ctor 0x893950) — no 512:440 split, already
resolution-dependent, but stretched horizontally off 4:3 (the bug KPM's
K2AspyrMapAspectFix fixes on GOG). MapHider::Draw 0x895CC0 multiplies conversion
results by the same xs/ys (`[ebp-0x14]/[ebp-0x20]`), steps the fog by
`xs·588/gridW`, and sizes every marker as `GetGuiScale()·{20,14,16,32}` with
centring `size/2`. So **all twelve K1 MapHider::Draw operand patches and the three
coordinate wrappers are not needed**; what K2 needs instead is an aspect fix on xs
(ctor convergence point 0x893E7A, and the Draw scales), analogous to KPM's GOG hooks
but with different frame offsets (Steam ctor: xs `[ebp-0x10]`, ys `[ebp-0x14]`,
this `[ebp-0xCC]`; Draw: GUI scale `[ebp-0x10]`, xs `[ebp-0x14]`, ys `[ebp-0x20]`).
`lbl_mapcircle` is still a fixed 16x16 (0x89588B/0x895895). InGameMap::Draw 0x894CD0
keeps K1's 640/480 centring (0x894D1B/0x894D35) and its mouse path 0x894DC0 has the
same pair (0x894E00/0x894E1C): change both or neither (that is why K1's vtable
hit-test wrapper is not needed). The HUD minimap does not use CSWGuiInGameMap
(DrawMap 0x750790 + fog 0x751230), so K1's minimap-ctor wrapper is not needed.
Offsets: InGameMap `+0x68` LBL_Map, `+0x1160` MapHider, `+0x13B8` canvas, `+0x140C`,
`+0x1410` flags; MapHider `+0x60` blackdot tex, `+0x64` arrow, `+0x68` circle,
`+0x6C` selected-note control, `+0x23C/+0x240` note controls array/count, `+0x24C`
selected note id, `+0x254` enabled.

### Dialogue — `CSWGuiDialogLetterbox` (0x9A7CBC), `CSWGuiDialogTop` (0x9A7D3C), `CSWGuiDialogCinematic` (0x9A7DCC)
Same width-derived bar as K1: `bar = (H − ftol(W / (7/3)))/2` with the single double
`0x9A7D30 = 2.3333` (K1 multiplied by float 0.428571 at 0x755788 and a second scalar
at 0x755AE4). Exactly seven readers (TSV row 00755788). At 21:9 `W/2.333 = H` → zero
bar, as in K1. **Smallest correct K2 port of KMRP's H/6 rule:** change the `movsx …,
[reg+0x6C]` (width) disp8 to `0x6E` (height) at the seven sites — 0x8BACE2, 0x8BADE2,
0x8BAF67, 0x8BB69C, 0x8BB99F, 0x8BBC18, 0x8BC460 — and set the double at 0x9A7D30 to
1.5 (`00 00 00 00 00 00 F8 3F`): `bar = (H − 2H/3)/2 = H/6`, and the Cinematic
constructor's `(H + 2H/3)/2 = 5H/6` stays consistent. (ftol truncation instead of
K1's `(x+3)/6` rounding: ≤1 px.) Cinematic offsets: LB_REPLIES `+0x2760` (flags
`+0x27A8`), LBL_MESSAGE `+0x2A50`, embedded DialogTop `+0x2BB0`, `+0x2BBC`;
Letterbox mode `+0x88` (1 top, 2 bottom, 3 full), alpha `+0x50` (KPM).

## 3. Member offsets determined (K2 Steam)

| class | member | offset | evidence |
| --- | --- | --- | --- |
| CSWGuiManager | mouse x / y | 0x0 / 0x4 | HandleMouseMove 0x412C0F/0x412C17 |
| CSWGuiManager | captured control | 0x10 | 0x412C94 |
| CSWGuiManager | 3D cursor model | 0x24 | 0x412C1D, 0x413650 "gui_mouse" |
| CSWGuiManager | tooltip | 0x3C | 0x414090 |
| CSWGuiManager | viewport w / h (short) | 0x6C / 0x6E | SetSize 0x411A8C |
| CSWGuiManager | panels / count | 0x88 / 0x8C | Update 0x41187C |
| CSWGuiManager | modal panels / count | 0x94 / 0x98 | Update, RescalePanels |
| CClientExoAppInternal | gui_in_game | 0x40 | SetVideoMode → 0x7CFCA0 |
| CClientExoAppInternal | current video mode | 0x1A0 | SetVideoMode 0x78DD5C |
| CClientExoAppInternal | gui_manager / load_screen / main_menu | 0x274 / 0x278 / 0x280 | SetVideoMode, 0x73FEA0 |
| CClientExoAppInternal | rumble patterns / count / queue | 0x340 / 0x344 / 0x34C,0x350 | PlayRumblePattern 0x79D402.. |
| CGuiInGame | in_game_map / manager | 0x24 / 0x38 | 0x7BF6xx, 0x7D0A2x |
| CExoMoviePlayerInternal | bink / buffer / hwnd / dest x,y | 0x48 / 0x4C / 0x50 / 0x84,0x88 | InitializeMovie, ShutDown |
| CSWGuiPanel | manager / active control / flags | 0x1C / 0x20 / 0x48 | everywhere (also KPM K2 GOG) |
| CSWGuiOptionsResolution | label / list / ok / cancel / reinit flag | 0x68 / 0x1B0 / 0x4A0 / 0x670 / 0x840 | ctor 0x7D8540, HIE 0x7D908D |
| CSWGuiInGameMap | MapHider / canvas | 0x1160 / 0x13B8 | ctor 0x893EC3/0x893F23 |
| CSWGuiMainInterface | minimap label / arrow / view rect / scaled size | 0x5AB4 / 0x5BFC / 0x5D44..0x5D50 / 0x5D54,0x5D58 | DrawMap 0x750790, DrawMapFog 0x751230 |
| CSWGuiMainInterface | Aspyr x/y scale floats | 0x1C9C / 0x1CA0 | ctor 0x74793F.. |
| CSWGuiDialogCinematic | LB_REPLIES / LBL_MESSAGE / DialogTop | 0x2760 / 0x2A50 / 0x2BB0 | SetExtent 0x8BC050, SetReplies 0x8BC230 |
| CSWPlayerControlCamRelative | up_down / left_right / walking | 0x10 / 0x14 / 0x18 | Control 0x865830 |

## 4. Overlaps with KPM's existing K2 Steam patches

Checked against every `Patches/*/kotor2-steam-aspyr.hooks.toml`. **No K2 site in
`map-screen.tsv` lies on or within 16 bytes of a KPM Steam hook.** Nearest
neighbours: SemiTransparentLetterbox (0x8BAA5E ctor, 0x8BB043 ResetFade, 0x8BB108
SetFade, 0x8BB3C3 Draw) is in the same class as the letterbox bar sites but in other
functions; DeSteamify's callback no-ops 0x40C3D5–0x40C491 sit just before the movie
wndproc 0x40C4A0; BorderlessFullscreen 0x476D69 is in the display-mode code
(0x476BE0) KMRP does not touch. K2AspyrMapAspectFix, ExpandedKeyboardControl and
Movie Patch have **GOG-only** K2 hooks; their logic transfers (the keyboard capture
site matches byte-for-byte) but their frame offsets differ on Steam (map ctor).

## 5. Open / blocking

* Not found: AnimationParry, ResolveCreaturePoweredAnimations, AurTextureGetMaxTexID,
  AddPartToMeshBuckets, ~CAurTriangleBin, DestroyGrassPolys (need a K1 disassembly to
  match shapes).
* Camera site 0x783148 depends on 0x78C350 being UpdateCamera (likely, unproven).
* Whether InGameMap::Draw's 640/480 centring still runs depends on panel flag bit0,
  which Aspyr's loader sets for scaled layouts; verify in a running game before
  patching 0x894D1B/0x894D35.
* Hook handlers written for K1 register sources must be rewritten for EBP frames.

## 6. What Aspyr does at 3840x2160 (owner's setup: Steam Deck docked to a 4K TV)

All figures computed from the code paths above; nothing was run.

* **Design size is a constant.** 0x9F4390 = 800 and 0x9F4394 = 600 have 10 readers each
  and **no writers** in the image (xrefs: all READ, in StartLoadFromLayout 0x40EE40,
  InitControl 0x40F620, HUD ctor 0x747210, map ctor 0x893950, map setup 0x894320,
  MapHider::Draw 0x895CC0, 0x8BDF50, 0x899CB0, 0x8FB130), so they never change at run time.
* **Enumeration / limits.** 3840x2160x32 is listed and accepted when it is ≤ the desktop
  size `GetDesktopWindow/GetWindowRect` reports (0x93C9C0, cached once in 0xA80D90/8C)
  and ≥ 1024x720; refresh only has to be ≥ 30 because w ≥ 2000 (0x7D8540, 0x93CA40), so a
  4K30 TV mode is offered. There is no upper cap anywhere in the path (no width compare
  above 2000; viewport is a signed short, fine to 32767). **Risk on the Deck:** the check
  is against the desktop rectangle, cached at first call. Under Proton/gamescope the
  "desktop" is whatever gamescope exposes; if that is the Deck's 1280x800 (gamescope
  output not set to 4K), 3840x2160 is filtered out of the list and an ini value of
  3840x2160 is rejected at startup (falls back to the largest fitting mode / 1024x768,
  0x78A7A0). Run gamescope at 3840x2160 (`-W 3840 -H 2160`) so the desktop is 4K.
* **Design scale at 16:9 4K.** Panels and controls are scaled by xs = 3840/800 = 4.8,
  ys = 2160/600 = 3.6: everything loaded with the scale flag is **stretched 1.333x
  horizontally** (4:3 layouts filling 16:9). The HUD (flag 0xA1B9F0 set by its ctor) gets
  InitControl's 4:3 re-projection (0x987488 = 1.3333 / (W/H)), so the HUD keeps its
  aspect. `CSWGuiManager::Draw` scissor-clears pillarbox bars because W/H = 1.78 > 1.3333
  (only in its mode 2). `GetGuiScale` = 1 + 0.5*floor((3840−1022)/1024) = **2.0**.
  Panel recentring that still uses (W−640)/2,(H−480)/2 (0x40EB17.., K2 uses `SUB EAX,+640`
  not K1's `ADD EAX,-640`; also InGameMap 0x894D1A/0x894DFF) gives offsets 1600/840 when
  a panel's scaled bit0 is clear.
* **Area map.** Canvas and marker overlay both ftol(4.8*588) x ftol(3.6*294) =
  **2822 x 1058** (a 2.667:1 box for a 2:1 map: 1.333x too wide, same stretch KPM's GOG
  fix addresses). Markers ×2.0: selected note 40, unselected 28, party 32, arrow 64 (arrow
  extent in the ctor also 64); `lbl_mapcircle` stays **16x16** (unscaled, tiny at 4K).
  Fog cells follow the stretched overlay, so fog stays aligned with the picture; draw and
  hit-test use the same offsets, so clicking still lines up.
* **HUD minimap.** Rect and scaled map size come from the HUD's aspect-corrected scale
  (+0x5D44..+0x5D58), fog grid uses the same basis; no break found.
* **Movies.** Movie window = main client rect 3840x2160. Scale = 3840 / movieW applied to
  both axes (width-only): a 4:3 640x480 movie becomes 3840x2880, offset y = (2160−2880)/2
  = −360, i.e. **360 rows cut off top and bottom**; a 16:9 movie fits exactly. Movies
  narrower than 16:9 therefore crop at 4K exactly as K1 did; the aspect-fit hook at
  0x40D218 fixes it. No display-mode change for movies (0x40BE50 re-inits at 3840x2160).
* **Letterbox.** bar = (2160 − ftol(3840/2.3333 = 1645.7))/2 = **257 px** per bar (12% of
  H; KMRP's H/6 would be 360). Not broken at 16:9 — the zero-bar failure needs
  W/H ≥ 2.333 (ultrawide). Dialogue reply area height = 100 * 2.0 = 200 px.
* **Nothing found that caps or overflows at 3840x2160** besides the desktop-size filter
  above: integer maths are 32-bit, the GL viewport stack (0x479460) only rejects rects
  starting beyond screenW/H, and RescalePanels scales proportionally on a live switch.
