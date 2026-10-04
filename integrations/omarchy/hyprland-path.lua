-- Loaded by the line `omarchy-guardian protect` adds at the end of
-- ~/.config/hypr/hyprland.lua:
--   pcall(dofile, "/usr/lib/omarchy-guardian/hyprland-path.lua")
--
-- Omarchy's own default/hypr/envs.lua puts its command directory first on
-- the PATH of everything Hyprland starts, and its autostart hands that PATH
-- to the systemd user manager and to D-Bus. Its `omarchy`,
-- `omarchy-theme-install` and the rest would then be found before
-- Guardian's commands of the same names, by key bindings, launchers, the
-- menu, the bar and every shell but Bash. This runs after Omarchy's
-- defaults and before Hyprland starts anything, and puts Guardian's
-- directory first, Omarchy's right behind it.
--
-- PATH is read from the process as well as set through Hyprland, and both
-- directories are placed anew, so the outcome is the same whether or not
-- Omarchy's line is already in what os.getenv returns.

local guardian = "/usr/lib/omarchy-guardian/bin"

-- As default/hypr/paths.lua reads it: set and empty means unset.
local omarchy = os.getenv("OMARCHY_PATH")
if omarchy == nil or omarchy == "" then
  omarchy = "/usr/share/omarchy"
end
omarchy = omarchy:gsub("/+$", "") .. "/bin"

local kept = { guardian, omarchy }
for entry in (os.getenv("PATH") or "/usr/local/bin:/usr/bin"):gmatch("[^:]+") do
  if entry ~= guardian and entry ~= omarchy then
    table.insert(kept, entry)
  end
end

hl.env("PATH", table.concat(kept, ":"))
