# Promtect demo for charmbracelet/vhs — two beats: how easy to start, how it works.
#   cargo build --release && vhs docs/demo.tape   →   docs/demo.gif
# A stub `claude` on PATH (created by the render step) lets `guard claude` run
# cleanly in the recording without a live Anthropic session.

Output docs/demo.gif

Set FontSize 22
Set Width 1100
Set Height 520
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 42ms

Hide
Type "export PATH=$PWD/target/release:/tmp/ptdemo:$PATH && clear"
Enter
Show

Sleep 400ms
Type "# 1 · start protecting your AI tool — one command:"
Enter
Sleep 700ms
Type "promtect guard claude"
Enter
Sleep 2900ms

Type "# 2 · what it does to your prompt before the model sees it:"
Enter
Sleep 700ms
Type "echo 'deploy with key AKIAIOSFODNN7EXAMPLE' | promtect mask"
Enter
Sleep 3000ms
