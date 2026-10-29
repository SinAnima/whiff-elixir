ExUnit.start(exclude: [:slow])

# Ensure binary fixtures exist even if shell scaffolding was skipped.
Mix.Task.run("loadpaths")

fixture_dir = Path.join([__DIR__, "fixtures"])
File.mkdir_p!(fixture_dir)

jpeg =
  Base.decode16!(
    "FFD8FFE000104A46494600010100000100010000FFDB004300080606070605080707070909080A0C141D0C0B0B0C1912130F141D1A1F1E1D1A1C1C20242E2720222C231C1C2837292C30313434341F27393D38323C2E333432FFC0000B080001000101011100FFC4001F0000010501010101010100000000000000000102030405060708090A0BFFDA0008010100003F007F4680FFD9",
    case: :mixed
  )

File.write!(Path.join(fixture_dir, "tiny.jpg"), jpeg)

pdf = """
%PDF-1.1
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 3 3] >>endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer<< /Size 4 /Root 1 0 R >>
startxref
178
%%EOF
"""

File.write!(Path.join(fixture_dir, "tiny.pdf"), pdf)
File.write!(Path.join(fixture_dir, "corrupt.pdf"), "%PDF-1.4\nnot a real pdf<<<<")
File.write!(Path.join(fixture_dir, "secret.secret"), "secret file\n")
File.write!(Path.join(fixture_dir, "hang.slow"), "slow\n")
File.write!(Path.join(fixture_dir, "café.txt"), "unicode name\n")

# Minimal ZIP (stored "hi.txt" -> "hi\n") via :zip
zip_path = Path.join(fixture_dir, "sample.zip")

:zip.create(
  String.to_charlist(zip_path),
  [{~c"hi.txt", "hi\n"}],
  []
)

nested_inner = Path.join(fixture_dir, "_inner.zip")

:zip.create(
  String.to_charlist(nested_inner),
  [{~c"inner.txt", "nested\n"}],
  []
)

inner_bin = File.read!(nested_inner)

:zip.create(
  String.to_charlist(Path.join(fixture_dir, "nested.zip")),
  [{~c"inner.zip", inner_bin}],
  []
)

File.rm(nested_inner)
