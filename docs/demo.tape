# Promtect demo tape for charmbracelet/vhs.
# Render from the crate root (so target/release/promtect is on PATH):
#   cargo build --release && vhs docs/demo.tape   →   docs/demo.gif

Output docs/demo.gif

Set FontSize 18
Set Width 1000
Set Height 500
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms

# Setup, invisibly: put the built binary on PATH and define the masked-exchange
# helper so only its output shows on screen (no `echo` command clutter).
Hide
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "flow(){ printf 'you      > fix the upload in s3.py   (file has AKIAIOSFODNN7EXAMPLE)\n  promtect > masked aws_key -> «promtect:aws_key:0001»   (the model never sees it)\n  claude   > here is the fix, using AKIAIOSFODNN7EXAMPLE   (restored in the response)\n'; }"
Enter
Type "clear"
Enter
Show

Sleep 250ms
Type "# Promtect — your API keys never reach the LLM"
Enter
Sleep 400ms

# Real, offline proof the masking pipeline is wired correctly.
Type "promtect selftest"
Enter
Sleep 1200ms

Type "# point Claude / Cursor / Codex at Promtect — secrets are masked at the door:"
Enter
Sleep 500ms

Type "flow"
Enter
Sleep 2200ms
