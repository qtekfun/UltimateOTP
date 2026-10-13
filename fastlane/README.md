# Store metadata (F-Droid, Fastlane layout)

F-Droid reads this directory straight from the tagged source (`fastlane/metadata/android/<locale>/`),
so a text fix reaches the store with the next tag and needs no change to the F-Droid recipe.
This directory belongs to the release work, not to the app's string resources.

| File | Limit | Notes |
|---|---|---|
| `title.txt` | 30 characters | |
| `short_description.txt` | 80 characters | one line, no full stop needed |
| `full_description.txt` | 4000 characters | F-Droid renders `<b>`, `<i>`, `<br>` and `•` lists only |
| `changelogs/<versionCode>.txt` | 500 bytes | named by `versionCode`, not by `versionName` |
| `images/icon.png` | 512 x 512 px, PNG | **not added yet**: waits for the redesign's logo |
| `images/featureGraphic.png` | 1024 x 500 px, PNG | **not added yet**: same |
| `images/phoneScreenshots/1.png`, `2.png`, ... | any phone size, PNG or JPG | **not added yet**: take them from the final UI, with invented data only |

Locales: `en-US` (the default) and `es-ES`. The `images/` directories hold `.gitkeep` files so the
paths exist; delete the placeholder when the real file is added. The `images/` paths are reserved
for the redesign: do not put placeholder artwork there.

Changelogs: see RELEASING.md ("Changelog files per versionCode"). `4.txt` is written ahead of
0.1.3 and must be checked against `CHANGELOG.md` when 0.1.3 is released.
