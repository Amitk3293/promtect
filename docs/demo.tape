# Promtect demo tape for charmbracelet/vhs.
# Render from the crate root (so target/release/promtect is on PATH):
#   cargo build --release && vhs docs/demo.tape   →   docs/demo.gif

Output docs/demo.gif

Set FontSize 20
Set Width 1180
Set Height 680
Set Padding 26
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

# Put the built binary on PATH, invisibly.
Hide
Type "export PATH=$PWD/target/release:$PATH && clear"
Enter
Show

Sleep 600ms
Type "# Promtect — your API keys never reach the LLM"
Enter
Sleep 900ms

# Real, offline proof that masking works.
Type "promtect selftest"
Enter
Sleep 1600ms

Type "# point your AI tool at Promtect; secrets are masked at the door:"
Enter
Sleep 900ms

Type "echo 'you      > fix the upload in s3.py   (file has AKIAIOSFODNN7EXAMPLE)'"
Enter
Sleep 700ms
Type "echo '  promtect > masked aws_key -> «promtect:aws_key:0001»   (model never sees your key)'"
Enter
Sleep 900ms
Type "echo '  claude   > here is the fix, using AKIAIOSFODNN7EXAMPLE   (restored in the response)'"
Enter
Sleep 2600ms
