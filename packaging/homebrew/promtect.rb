# Homebrew formula for Promtect.
#
# This is the template for the `promtect/homebrew-tap` repository, enabling:
#   brew install promtect/tap/promtect
#
# Before the first release, fill in `url` and `sha256` for the published source
# tarball (a release workflow can template these automatically per tag).
class Promtect < Formula
  desc "Local-first privacy proxy for AI coding tools: mask secrets before the LLM, restore them after"
  homepage "https://promtect.dev"
  license "Apache-2.0"

  # TODO(release): point at the tagged source tarball and its sha256.
  url "https://github.com/amitk3293/promtect/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  version "0.1.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    # selftest proves the masking pipeline works with no network access.
    assert_match "PASS", shell_output("#{bin}/promtect selftest")
  end
end
