# Promtect demo for charmbracelet/vhs — two beats: how easy to start, how it works.
#   cargo build --release && vhs docs/demo.tape   →   docs/demo.gif
# A stub `claude` on PATH (created by the render step) lets `guard claude` run
# cleanly in the recording without a live Anthropic session.

Output docs/demo.gif

Set FontSize 20
Set Width 1480
Set Height 540
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms

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

Type "# 2 · every secret — keys, tokens, DB passwords — masked before the model sees it:"
Enter
Sleep 700ms
Type "echo 'aws AKIAIOSFODNN7EXAMPLE  db postgres://app:hunter2@prod  stripe sk_live_4eC39HqLyjWDarjtT1zdp7dc' | promtect mask"
Enter
Sleep 3200ms
