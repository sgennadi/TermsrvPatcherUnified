using System.Buffers.Binary;
using TermsrvPatcherUnified.Core;

int assertions = 0;
void Ensure(bool condition, string message)
{
    assertions++;
    if (!condition) throw new Exception("FAILED: " + message);
}

void Expect<TException>(Action action, string message) where TException : Exception
{
    bool threw = false;
    try { action(); }
    catch (TException) { threw = true; }
    Ensure(threw, message);
}

byte[] FakeBytes(BytePattern group, int offset = 40)
{
    var value = Enumerable.Repeat((byte)0xFA, 256).ToArray();
    for (int i = 0; i < group.Search.Length; i++)
        value[offset + i] = group.Search[i] ?? 0x73;
    return value;
}

var signature = new BytePattern("11 * 33 44", "90 90 90 90");
var bytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44 };
Ensure(BytePattern.FindOffsets(bytes, signature.Search).SequenceEqual([1]), "wildcard matches");
Ensure(BytePattern.FindOffsets(new byte[] { 0x11, 0x55, 0x33, 0x44 }, signature.Search).SequenceEqual([0]),
    "matches last possible offset");
Ensure(BytePattern.FindOffsets(new byte[] { 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44 },
    signature.Search).Count == 2, "ambiguous repeated signature");
Ensure(BytePattern.FindOffsets(bytes, signature.Search, 0).Count == 0, "max results limit");
Expect<FormatException>(() => BytePattern.ParseFind("A B C D"), "reject single hex digits");
Expect<FormatException>(() => BytePattern.ParseReplace("ZZ 11 22 33"), "reject invalid HEX");
Expect<ArgumentException>(() => new BytePattern("* * * *", "11 22 33 44"), "reject all wildcards");

var automatic = PatchCatalog.LoadAutomatic();
Ensure(automatic.Count == 3, "automatic catalog contains three upstream families");
Ensure(automatic.All(p => p.Architecture == "x64"), "automatic catalog uses x64");
foreach (var profile in automatic)
{
    var source = FakeBytes(profile.Groups.Single());
    string sha = SystemInfo.Sha256(source);
    var plan = PatchCatalog.Inspect(source, "fake.dll", "1.0", sha, true, [profile]);
    Ensure(plan.State == PatchState.Ready, "auto signature ready: " + profile.Label);
    Ensure(plan.Edits.Single().Offset == 40, "auto signature offset: " + profile.Label);
    Ensure(plan.PatchedBytes is not null && !source.SequenceEqual(plan.PatchedBytes),
        "replacement different: " + profile.Label);
    var patched = PatchCatalog.Inspect(plan.PatchedBytes!, "fake.dll", "1.0", "patched", true, [profile]);
    Ensure(patched.State == PatchState.AlreadyPatched, "already-patched recognition: " + profile.Label);
}

var old = PatchCatalog.Parse("# Windows 10 22H2\nx64, 11 22 33 44, AA BB CC DD\n");
Ensure(old.Count == 1 && old[0].Label.StartsWith("Windows 10"), "manual catalog labels");
var made = FakeBytes(new BytePattern("11 22 33 44", "AA BB CC DD"));
var ready = PatchCatalog.Inspect(made, "fake.dll", "1.0", SystemInfo.Sha256(made), true, old);
Ensure(ready.State == PatchState.Ready, "manual unique known signature ready");
Ensure(ready.PatchedBytes![40] == 0xAA, "preview changes expected byte");
Ensure(PatchCatalog.Inspect(ready.PatchedBytes!, "fake.dll", "1.0", "patched", true, old).State ==
    PatchState.AlreadyPatched, "manual already-patched recognition");
Ensure(PatchCatalog.Inspect(new byte[100], "fake.dll", "1.0", "test", true, old).State == PatchState.Unknown,
    "no match is unknown");
Ensure(PatchCatalog.Inspect(made, "fake.dll", "1.0", "test", false, old).State == PatchState.Unsupported,
    "unsupported target blocked");
new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(made, 80);
Ensure(PatchCatalog.Inspect(made, "fake.dll", "1.0", "test", true, old).State == PatchState.Ambiguous,
    "repeated pattern blocked");

var grouped = PatchCatalog.Parse("# Windows grouped\nx64, 11 22 33 44 | 55 66 77 88, AA BB CC DD | EE FF 00 01");
var groupedBytes = Enumerable.Repeat((byte)0xFA, 256).ToArray();
new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(groupedBytes, 16);
new byte[] { 0x55, 0x66, 0x77, 0x88 }.CopyTo(groupedBytes, 90);
var groupPreview = PatchCatalog.Inspect(groupedBytes, "fake.dll", "1.0", "test", true, grouped);
Ensure(groupPreview.State == PatchState.Ready && groupPreview.Edits.Count == 2,
    "multi-group patch stays atomic");
Ensure(PatchCatalog.Inspect(groupPreview.PatchedBytes!, "fake.dll", "1.0", "test", true, grouped).State ==
    PatchState.AlreadyPatched, "multi-group already patched");
new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }.CopyTo(groupedBytes, 16);
Ensure(PatchCatalog.Inspect(groupedBytes, "fake.dll", "1.0", "test", true, grouped).State == PatchState.Ambiguous,
    "partially modified multi-group blocked");
Expect<FormatException>(() => PatchCatalog.Parse("x64, 11 22 33 44, 44 55 66"),
    "reject groups with different lengths");
Expect<FormatException>(() => PatchCatalog.Parse("arm64, 11 22 33 44, 44 55 66 77"),
    "reject unsupported architecture");
Ensure(PatchCatalog.Manual("11 * 33 44 | 55 66 77 88", "AA BB CC DD | 90 90 90 90").Groups.Count == 2,
    "manual multi-group parsing");

var near = FakeBytes(automatic[1].Groups.Single());
near[40 + 12] ^= 1; // Change just the last fixed byte in the 24H2 family.
Ensure(PatchCatalog.Inspect(near, "fake.dll", "1.0", "test", true, automatic).State == PatchState.Unknown,
    "changed automatic signature no longer trusted");
var suggestions = NearMatchFinder.Find(near, automatic);
Ensure(suggestions.Any(s => s.Offset == 40 && s.DifferentByteIndexes.SequenceEqual([12])),
    "read-only similarity finds one differing byte");
Ensure(NearMatchFinder.Find(new byte[256], automatic).Count == 0,
    "no false near-match from all-zero data");

// A deliberately minimal in-memory AMD64 PE DLL, used only for header and range tests.
var pe = new byte[0x500];
pe[0] = (byte)'M'; pe[1] = (byte)'Z';
BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C, 4), 0x80);
new byte[] { (byte)'P', (byte)'E', 0, 0 }.CopyTo(pe, 0x80);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x84, 2), 0x8664);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x86, 2), 1);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x94, 2), 0xF0);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x96, 2), 0x2000);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x98, 2), 0x20B);
int section = 0x80 + 24 + 0xF0;
BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 16, 4), 0x100);
BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 20, 4), 0x200);
BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 36, 4), 0x60000020);
Ensure(PeSafety.ReadAmd64DllSections(pe).Count == 1, "AMD64 DLL sections recognized");
PeSafety.RequireExecutableEdits(pe, [new PatchEdit(0x220, [1, 2, 3, 4], [5, 6, 7, 8])]);
assertions++;
Expect<InvalidDataException>(() => PeSafety.RequireExecutableEdits(pe,
    [new PatchEdit(0x100, [1, 2, 3, 4], [5, 6, 7, 8])]), "reject edit inside PE headers");
Expect<InvalidDataException>(() => PeSafety.RequireExecutableEdits(pe,
    [new PatchEdit(0x2FE, [1, 2, 3, 4], [5, 6, 7, 8])]), "reject edit crossing section boundary");
var notDll = (byte[])pe.Clone();
BinaryPrimitives.WriteUInt16LittleEndian(notDll.AsSpan(0x96, 2), 0);
Expect<InvalidDataException>(() => PeSafety.ReadAmd64DllSections(notDll), "reject non-DLL PE");
Expect<InvalidDataException>(() => PeSafety.ReadAmd64DllSections(new byte[200]), "reject non-PE file");

// Check native library platform gates without loading any native code.
Ensure(!NsudoDevilModeScope.IsBundled || OperatingSystem.IsWindows(),
    "embedded native NSudo package must be a Windows build resource");
var nativePe = (byte[])pe.Clone();
NsudoDevilModeScope.EnsureAmd64Dll(nativePe);
assertions++;
Expect<InvalidDataException>(() => NsudoDevilModeScope.EnsureAmd64Dll(new byte[100]),
    "native NSudo rejects a non-PE file");
Expect<InvalidDataException>(() => NsudoDevilModeScope.EnsureAmd64Dll(notDll),
    "native NSudo rejects a non-DLL file");
Console.WriteLine($"PASS: {assertions} TermsrvPatcher Unified read-only and preflight assertions.");
