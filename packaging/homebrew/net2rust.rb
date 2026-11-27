class Net2rust < Formula
  desc "55 pure-Rust network diagnostics, ETW capture, LAN, OSINT, and Wi-Fi/BLE tools with Iced GUI, CLI, and MCP server"
  homepage "https://guap.ca/net2rust/"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/net2rust/releases/download/v0.1.0/net2rust-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/adpaolucci/net2rust/releases/download/v0.1.0/net2rust-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/net2rust/releases/download/v0.1.0/net2rust-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "net2rust"
    bin.install "net2rust-iced"
    bin.install "net2rust-mcp"
    doc.install "README.md", "CHANGELOG.md"
    doc.install "SBOM-crates.txt" if File.exist?("SBOM-crates.txt")
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "net2rust", shell_output("#{bin}/net2rust --help")
    assert_match "net2rust-mcp", shell_output("#{bin}/net2rust-mcp --help")
    assert_match "net2rust-iced", shell_output("#{bin}/net2rust-iced --help")
  end
end
