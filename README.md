# VanaView

> [!IMPORTANT]
> **This repository is archived and no longer maintained.**
> Please use the updated fork: **https://github.com/By-T0r/VanaView**

An [Ashita v4](https://www.ashitaxi.com/) plugin for **Final Fantasy XI**.

VanaView adds an ImGui window for tuning the client's visual distance, map
level-of-detail behavior, and fog behavior. It is meant to reduce world pop-in
and make distant map props such as trees, flowers, and terrain details appear
more consistently.

This is a **client-side visual plugin only**. It does not change movement speed,
combat, cooldowns, NPC behavior, server state, or how other players see you.

## Features

- Fixed-size ImGui configuration window with a neutral dark theme and inline
  `(?)` tooltips.
- Smooth `Distance` slider for world/entity draw distance. The default slider
  value is `20`.
- `Map LoD` controls:
  - `Range`: extends the distance before map objects switch to lower LoD.
  - `Full`: forces the highest available map LoD where supported.
- `Fog` controls:
  - `Distance`: uses the game's fog exactly as emitted, so it follows the
    raised draw distance.
  - `Game`: uses the last natural fog range captured from the game and reapplies
    it while keeping raised draw distance.
  - `Custom`: forces the manually configured fog start/end values.
- AMD/dgVoodoo-friendly fog override path for `Game` and `Custom` fog modes.
- Global profile by default, with optional per-zone profiles. Zones without a
  saved profile fall back to the global profile.
- Restores the original client values when unloaded. The `Default` button and
  `/vv reset` apply VanaView's default profile values.

Default profile values on first load or after pressing `Default` are:

- Global profile mode (`Use zone profiles` disabled).
- `Distance`: `20`.
- `Map LoD`: `Full`.
- `Fog`: `Game`.

## Install

1. Download `VanaView.dll` from the [latest release](../../releases) (or the
   `dist/` folder).
2. Copy it into your Ashita plugins folder:

   ```text
   Ashita/plugins/VanaView.dll
   ```

3. Load it in game:

   ```text
   /load vanaview
   ```

4. Open the window:

   ```text
   /vv
   ```

## Commands

| Command | Description |
| --- | --- |
| `/vv` or `/vanaview` | Toggle the configuration window. |
| `/vv status` | Show the current distance, LoD, and fog state. |
| `/vv distance <1-100>` | Set draw distance using the same smooth scale as the UI slider. |
| `/vv distance default` | Restore the original draw distance captured from the client. |
| `/vv lod <scale>` | Enable LoD range mode. `1.00` is the normal game distance; higher values extend it. |
| `/vv lod full` | Force highest map LoD where the current client code path supports it. |
| `/vv lod default` | Restore the game's normal LoD behavior. |
| `/vv fog <start> <end>` | Enable custom fog range. |
| `/vv fog custom` | Use the current custom fog start/end values. |
| `/vv fog game` or `/vv fog natural` | Use the last natural fog range captured from the game. |
| `/vv fog distance` or `/vv fog linked` | Use the game's fog exactly as emitted, linked to current draw distance. |
| `/vv fog default` | Switch fog to distance-linked mode. |
| `/vv zone on` | Enable per-zone profiles. |
| `/vv zone off` | Disable per-zone profiles and return to the global profile. |
| `/vv zone status` | Show whether per-zone profiles are enabled, the current zone id, and whether the active profile is zone or global. |
| `/vv reset` | Restore the current profile to VanaView defaults. |

## Configuration

Settings are saved to:

```text
Ashita/config/plugins/VanaView.ini
```

By default, VanaView uses one global profile. If `Use zone profiles` is enabled,
VanaView loads a zone profile only when one already exists. Zones without a saved
profile use the global profile until you press `Save` while that zone is active.

Zone profiles are saved under their own INI section, such as:

```text
[zone.101]
distance=...
lod_mode=...
lod_range=...
fog_mode=...
fog_start=...
fog_end=...
```

When changing zones, VanaView saves the previous zone profile only if that zone
already had its own profile, then loads the next zone profile if present. This
prevents empty zone profiles from being created just by zoning through an area.

## Notes

Increasing distance and LoD can make the game render more objects and higher
detail meshes, which may lower FPS depending on the zone and hardware.

Fog modes have different tradeoffs:

- `Distance` leaves the game's fog render states alone, so fog remains linked to
  the modified draw distance.
- `Game` reapplies the last natural fog range captured from the game while raised
  draw distance is active. It refreshes when the game sends new fog values, such
  as zone or weather updates.
- `Custom` intentionally overrides the game's own fog start/end values.

On some AMD/dgVoodoo setups, table fog and range fog do not behave the same as
they do on the original developer's NVIDIA setup. `Game` and `Custom` fog modes
force a vertex-fog path so fog applies more consistently across models.

VanaView does not send packets and does not interact with server-side systems.

## Building from source

Requires the **Visual Studio 2022 C++ x86 build tools**. FFXI is a 32-bit
process, so the plugin must be built as x86.

1. Make sure the Ashita plugin SDK headers are available and set `ASHITA_SDK`
   to the folder that contains `Ashita.h`.
2. Run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File build.ps1
   ```

   This produces `dist/VanaView.dll`.

## License

Released under the MIT License. See [LICENSE](LICENSE).

## Credits

Created by **rockerudon**.

AMD/dgVoodoo fog investigation, profile behavior changes, UI/default updates,
and local Ashita testing by **By-T0r**.

The draw distance control is based on the same client values used by the Ashita
`drawdistance` addon.

## Support

If you find this project useful, you can support development here:

<a href="https://www.buymeacoffee.com/rockmizx" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50" width="210"></a>
