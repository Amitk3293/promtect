# Promtect demo for charmbracelet/vhs — two beats: how easy to start, how it works.
#   cargo build --release && vhs docs/demo.tape   →   docs/demo.gif
# A stub `claude` on PATH (created by the render step) lets `guard claude` run
# cleanly in the recording without a live Anthropic session.

Output docs/demo.gif

Set FontSize 20
Set Width 1280
Set Height 500
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 38ms

Hide
Type "export PATH=$PWD/target/release:/tmp/ptdemo:$PATH && clear"
Enter
Show

Sleep 700ms
Type "# 1 · protect your AI tool — one command"
Enter
Sleep 1200ms
Type "promtect guard claude"
Enter
Sleep 3800ms

Type "# 2 · secrets are masked before the model ever sees them"
Enter
Sleep 1200ms
Type "echo 'AKIAIOSFODNN7EXAMPLE  postgres://app:hunter2@prod' | promtect mask"
Enter
Sleep 4200ms
