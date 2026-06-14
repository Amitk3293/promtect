# Promtect demo tape for charmbracelet/vhs.
# Generate the README GIF with:  vhs docs/demo.tape   →   docs/demo.gif
#
# It shows: a secret in a prompt → Promtect masks it outbound → the model never
# sees it → the real value is restored in the answer.

Output docs/demo.gif

Set FontSize 20
Set Width 1200
Set Height 640
Set Padding 24
Set Theme "Catppuccin Mocha"

Type "# Promtect: your API keys never reach the LLM"
Enter
Sleep 1s

Type "promtect selftest"
Enter
Sleep 1500ms
# → promtect selftest: PASS — no leak

Type "# start the proxy and point Claude Code at it"
Enter
Sleep 800ms

Type "PROMTECT_PORT=8787 promtect &"
Enter
Sleep 1s

Type 'ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude "fix the upload in s3.py (has my AWS key)"'
Enter
Sleep 2s

Type "# outbound: the model sees  «promtect:aws_key:0001»  — never AKIA..."
Enter
Sleep 1500ms

Type "# inbound: Promtect restores your real key, so the answer just works"
Enter
Sleep 2s
